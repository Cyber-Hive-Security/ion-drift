//! Module registry — validates, initializes, and runs modules.
//!
//! The main entry point is [`ModuleRegistry::load`], which takes a list of
//! modules, constructs contexts, calls `init` on each, collects the returned
//! routers, and exposes a unified Axum `Router` to the host.

use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use futures::future::FutureExt;
use ion_drift_module_api::context::{
    BoxFuture, ModuleConfigHandle, ModuleContext, SecretResolver, SecretsHandle, ShutdownSignal,
    StateReadHandles, TaskSpawner, TaskSupervisorHandle,
};
use ion_drift_module_api::storage::StorageBackend;
use ion_drift_module_api::{
    ApiVersion, Capabilities, Module, ModuleError, ModuleStorage, StorageNeed,
};
use regex::Regex;

/// Extract a human-readable message from a panic payload.
fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<opaque panic payload>".to_string()
    }
}

use crate::event_bus::EventBus;
use crate::panic_guard::PanicGuardLayer;
use crate::storage_backend::SqliteBackend;

/// Status of a loaded module.
#[derive(Debug, Clone)]
pub enum ModuleStatus {
    /// Initialized successfully and has routes/health/etc.
    Running,
    /// Init failed; module is not active. The string is the human-readable
    /// reason shown in `/api/system/modules`.
    Disabled { reason: String },
}

/// A module after the host has loaded it. Held in the registry.
pub struct LoadedModule {
    pub name: &'static str,
    pub version: &'static str,
    pub api_version: ApiVersion,
    pub status: ModuleStatus,
    /// The module's returned router, if any.
    pub(crate) router: Option<Router>,
    /// The module's context, kept for future shutdown calls.
    pub(crate) context: Option<ModuleContext>,
    /// The trait object itself, for shutdown dispatch.
    pub(crate) module: Arc<dyn ModuleErased>,
}

/// Object-safe erased version of the `Module` trait.
///
/// The module-api `Module` trait uses native `async fn` which is not
/// dyn-compatible. We provide a parallel trait here that returns `BoxFuture`
/// from each method and a blanket impl that bridges any `Module` to it.
pub trait ModuleErased: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn api_version(&self) -> ApiVersion;
    fn capabilities(&self) -> Capabilities;
    fn init<'a>(
        &'a self,
        cx: ModuleContext,
    ) -> BoxFuture<'a, Result<ion_drift_module_api::ModuleRegistration, ModuleError>>;
    fn shutdown<'a>(&'a self, cx: &'a ModuleContext) -> BoxFuture<'a, ()>;
}

impl<M: Module> ModuleErased for M {
    fn name(&self) -> &'static str {
        Module::name(self)
    }
    fn version(&self) -> &'static str {
        Module::version(self)
    }
    fn api_version(&self) -> ApiVersion {
        Module::api_version(self)
    }
    fn capabilities(&self) -> Capabilities {
        Module::capabilities(self)
    }
    fn init<'a>(
        &'a self,
        cx: ModuleContext,
    ) -> BoxFuture<'a, Result<ion_drift_module_api::ModuleRegistration, ModuleError>> {
        Box::pin(Module::init(self, cx))
    }
    fn shutdown<'a>(&'a self, cx: &'a ModuleContext) -> BoxFuture<'a, ()> {
        Box::pin(Module::shutdown(self, cx))
    }
}

/// Dependencies the registry needs from the host to build module contexts.
pub struct HostDeps {
    pub data_dir: PathBuf,
    pub event_bus: EventBus,
    pub task_spawner: Arc<dyn TaskSpawner>,
    pub secret_resolver: Arc<dyn SecretResolver>,
    pub shutdown: ShutdownSignal,
    pub state_reads: StateReadHandles,
    /// Raw TOML `[modules]` table from ServerConfig.
    pub modules_config: toml::Table,
}

/// Registry of all loaded modules.
pub struct ModuleRegistry {
    modules: Vec<LoadedModule>,
}

impl ModuleRegistry {
    /// Validate, initialize, and load a list of modules.
    ///
    /// This is the single entry point. The returned registry holds the
    /// loaded modules, and [`Self::build_router`] produces the merged Axum
    /// router to install under `/api/modules`.
    pub async fn load(
        modules: Vec<Arc<dyn ModuleErased>>,
        deps: HostDeps,
    ) -> Self {
        let mut loaded: Vec<LoadedModule> = Vec::with_capacity(modules.len());
        let name_regex = Regex::new(r"^[a-z][a-z0-9_-]{1,31}$").expect("valid regex");
        let mut seen_names: std::collections::HashSet<&'static str> =
            std::collections::HashSet::new();

        for module in modules {
            let name = module.name();
            let version = module.version();
            let api_version = module.api_version();

            // Validate name
            if !name_regex.is_match(name) {
                tracing::error!(
                    module = %name,
                    "invalid module name (must match ^[a-z][a-z0-9_-]{{1,31}}$); refusing to load"
                );
                loaded.push(LoadedModule {
                    name,
                    version,
                    api_version,
                    status: ModuleStatus::Disabled {
                        reason: "invalid name".to_string(),
                    },
                    router: None,
                    context: None,
                    module: module.clone(),
                });
                continue;
            }

            // Uniqueness
            if !seen_names.insert(name) {
                tracing::error!(module = %name, "duplicate module name; refusing to load");
                loaded.push(LoadedModule {
                    name,
                    version,
                    api_version,
                    status: ModuleStatus::Disabled {
                        reason: "duplicate name".to_string(),
                    },
                    router: None,
                    context: None,
                    module: module.clone(),
                });
                continue;
            }

            // API version compat
            if !api_version.is_compatible_with(ApiVersion::CURRENT) {
                tracing::error!(
                    module = %name,
                    module_api = %api_version,
                    host_api = %ApiVersion::CURRENT,
                    "incompatible module API version; refusing to load"
                );
                loaded.push(LoadedModule {
                    name,
                    version,
                    api_version,
                    status: ModuleStatus::Disabled {
                        reason: format!(
                            "API version {} not compatible with host {}",
                            api_version,
                            ApiVersion::CURRENT
                        ),
                    },
                    router: None,
                    context: None,
                    module: module.clone(),
                });
                continue;
            }

            let capabilities = module.capabilities();

            // Validate declared secret names match the per-module namespace.
            // Names MUST be `MODULE_<UPPER_NAME>_*` where UPPER_NAME is the
            // module name with hyphens converted to underscores, uppercased.
            // This prevents modules from declaring secret names belonging to
            // Drift core (e.g. DRIFT_SESSION_SECRET) and exfiltrating them.
            let upper_name = name.replace('-', "_").to_uppercase();
            let required_prefix = format!("MODULE_{upper_name}_");
            let mut secret_violation: Option<&'static str> = None;
            for secret_name in &capabilities.secrets {
                if !secret_name.starts_with(&required_prefix) {
                    secret_violation = Some(secret_name);
                    break;
                }
            }
            if let Some(bad) = secret_violation {
                tracing::error!(
                    module = %name,
                    secret = %bad,
                    required_prefix = %required_prefix,
                    "module declared a secret name outside its required namespace; refusing to load"
                );
                loaded.push(LoadedModule {
                    name,
                    version,
                    api_version,
                    status: ModuleStatus::Disabled {
                        reason: format!(
                            "secret name '{bad}' must start with '{required_prefix}'"
                        ),
                    },
                    router: None,
                    context: None,
                    module: module.clone(),
                });
                continue;
            }

            // Check enabled flag in config
            let module_config_value = deps
                .modules_config
                .get(name)
                .cloned()
                .unwrap_or(toml::Value::Table(toml::map::Map::new()));
            if let toml::Value::Table(ref t) = module_config_value {
                if let Some(toml::Value::Boolean(false)) = t.get("enabled") {
                    tracing::info!(module = %name, "module disabled in config; skipping");
                    loaded.push(LoadedModule {
                        name,
                        version,
                        api_version,
                        status: ModuleStatus::Disabled {
                            reason: "disabled in config".to_string(),
                        },
                        router: None,
                        context: None,
                        module: module.clone(),
                    });
                    continue;
                }
            }

            // Build storage if requested
            let storage = match capabilities.storage {
                StorageNeed::None => None,
                StorageNeed::Isolated => {
                    match SqliteBackend::open(deps.data_dir.clone(), name).await {
                        Ok(backend) => {
                            let backend: Arc<dyn StorageBackend> = Arc::new(backend);
                            Some(ModuleStorage::new(backend))
                        }
                        Err(e) => {
                            tracing::error!(module = %name, error = %e, "failed to open module storage");
                            loaded.push(LoadedModule {
                                name,
                                version,
                                api_version,
                                status: ModuleStatus::Disabled {
                                    reason: format!("storage open failed: {e}"),
                                },
                                router: None,
                                context: None,
                                module: module.clone(),
                            });
                            continue;
                        }
                    }
                }
            };

            // Build event handle scoped to declared publish/subscribe sets.
            // The module name is passed so the host can stamp it onto any
            // ModuleCustom events published through this handle.
            let events = deps.event_bus.handle_for(
                name,
                capabilities.events.publish.clone(),
                capabilities.events.subscribe.clone(),
            );

            // Scoped task supervisor handle
            let task_handle = TaskSupervisorHandle::new(deps.task_spawner.clone());

            // Secrets
            let secrets = SecretsHandle::new(
                capabilities.secrets.clone(),
                deps.secret_resolver.clone(),
            );

            // State reads — only expose what was declared
            let mut state = StateReadHandles::default();
            if capabilities.state_reads.behavior {
                state.behavior = deps.state_reads.behavior.clone();
            }
            if capabilities.state_reads.switch {
                state.switch = deps.state_reads.switch.clone();
            }
            if capabilities.state_reads.connection {
                state.connection = deps.state_reads.connection.clone();
            }
            if capabilities.state_reads.snapshot {
                state.snapshot = deps.state_reads.snapshot.clone();
            }
            if capabilities.state_reads.devices {
                state.devices = deps.state_reads.devices.clone();
            }

            let config_handle = ModuleConfigHandle::new(module_config_value);
            let span = tracing::info_span!("module", name = %name);
            let cx = ModuleContext::new(
                name,
                span.clone(),
                config_handle,
                storage,
                state,
                events,
                task_handle,
                secrets,
                deps.shutdown.clone(),
            );

            // Call init inside the module's tracing span, with panic catching.
            // A panic in init MUST NOT crash Drift — the module is marked
            // Disabled and the rest of the load() pass continues.
            let cx_for_init = cx.clone();
            let module_for_init = module.clone();
            let span_for_init = span.clone();
            let init_result = AssertUnwindSafe(async move {
                let _entered = span_for_init.enter();
                module_for_init.init(cx_for_init).await
            })
            .catch_unwind()
            .await;

            match init_result {
                Ok(Ok(registration)) => {
                    tracing::info!(module = %name, version = %version, "module loaded");
                    loaded.push(LoadedModule {
                        name,
                        version,
                        api_version,
                        status: ModuleStatus::Running,
                        router: registration.router,
                        context: Some(cx),
                        module,
                    });
                }
                Ok(Err(e)) => {
                    tracing::error!(module = %name, error = %e, "module init failed");
                    loaded.push(LoadedModule {
                        name,
                        version,
                        api_version,
                        status: ModuleStatus::Disabled {
                            reason: format!("init failed: {e}"),
                        },
                        router: None,
                        context: None,
                        module,
                    });
                }
                Err(panic_payload) => {
                    let msg = panic_message(&panic_payload);
                    tracing::error!(module = %name, panic = %msg, "module init panicked");
                    loaded.push(LoadedModule {
                        name,
                        version,
                        api_version,
                        status: ModuleStatus::Disabled {
                            reason: format!("init panicked: {msg}"),
                        },
                        router: None,
                        context: None,
                        module,
                    });
                }
            }
        }

        Self { modules: loaded }
    }

    /// Build the merged Axum router containing all running modules' routes,
    /// each nested under `/<module-name>/` and wrapped in a panic guard.
    ///
    /// The returned router is expected to be `nest`ed by the host under
    /// `/api/modules`. When no modules are loaded, this returns an empty
    /// `Router::new()` — adding it to the main app has no effect.
    pub fn build_router(&mut self) -> Router {
        let mut merged = Router::new();
        for m in self.modules.iter_mut() {
            if let (ModuleStatus::Running, Some(router)) = (&m.status, m.router.take()) {
                let wrapped = router.layer(PanicGuardLayer::new(m.name));
                merged = merged.nest(&format!("/{}", m.name), wrapped);
            }
        }
        merged
    }

    /// Return a JSON-serializable summary of loaded modules, suitable for
    /// `GET /api/system/modules`.
    pub fn summary(&self) -> Vec<serde_json::Value> {
        self.modules
            .iter()
            .map(|m| {
                let (status_str, reason) = match &m.status {
                    ModuleStatus::Running => ("running", None),
                    ModuleStatus::Disabled { reason } => ("disabled", Some(reason.clone())),
                };
                serde_json::json!({
                    "name": m.name,
                    "version": m.version,
                    "api_version": format!("{}", m.api_version),
                    "status": status_str,
                    "reason": reason,
                })
            })
            .collect()
    }

    /// Number of modules currently loaded (including disabled ones).
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// True if no modules are loaded at all.
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// Find a loaded module by name (including disabled ones).
    pub fn get(&self, name: &str) -> Option<&LoadedModule> {
        self.modules.iter().find(|m| m.name == name)
    }

    /// Call shutdown on every running module. Best-effort; errors and panics
    /// are logged but never propagated. A panicking module's shutdown will
    /// not stop the host from shutting down other modules.
    pub async fn shutdown_all(&self) {
        for m in &self.modules {
            if let (ModuleStatus::Running, Some(cx)) = (&m.status, m.context.as_ref()) {
                let module = m.module.clone();
                let cx_clone = cx.clone();
                let span = cx.tracing_span().clone();
                let result = AssertUnwindSafe(async move {
                    let _entered = span.enter();
                    module.shutdown(&cx_clone).await;
                })
                .catch_unwind()
                .await;
                if let Err(payload) = result {
                    let msg = panic_message(&payload);
                    tracing::error!(module = %m.name, panic = %msg, "module shutdown panicked");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ion_drift_module_api::{
        Capabilities, Module, ModuleContext, ModuleError, ModuleRegistration,
    };

    /// A trivial module used for testing the registry. Does nothing on init.
    struct EmptyModule {
        name: &'static str,
        secrets: Vec<&'static str>,
    }

    impl Module for EmptyModule {
        fn name(&self) -> &'static str {
            self.name
        }
        fn version(&self) -> &'static str {
            "0.0.0"
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                secrets: self.secrets.clone(),
                ..Capabilities::default()
            }
        }
        async fn init(
            &self,
            _cx: ModuleContext,
        ) -> Result<ModuleRegistration, ModuleError> {
            Ok(ModuleRegistration::default())
        }
    }

    /// A module whose `init` panics.
    struct PanickingModule;

    impl Module for PanickingModule {
        fn name(&self) -> &'static str {
            "panicking"
        }
        fn version(&self) -> &'static str {
            "0.0.0"
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities::default()
        }
        async fn init(
            &self,
            _cx: ModuleContext,
        ) -> Result<ModuleRegistration, ModuleError> {
            panic!("intentional panic for test");
        }
    }

    fn build_test_deps() -> HostDeps {
        struct NoopSpawner;
        impl ion_drift_module_api::context::TaskSpawner for NoopSpawner {
            fn spawn(
                &self,
                _name: &str,
                _factory: Box<
                    dyn Fn() -> ion_drift_module_api::context::BoxFuture<'static, ()>
                        + Send
                        + Sync
                        + 'static,
                >,
            ) {
            }
        }
        struct NoopResolver;
        impl ion_drift_module_api::context::SecretResolver for NoopResolver {
            fn resolve(&self, _name: &str) -> Option<String> {
                None
            }
        }
        HostDeps {
            data_dir: std::env::temp_dir().join("ion-drift-test"),
            event_bus: crate::EventBus::new(64),
            task_spawner: Arc::new(NoopSpawner),
            secret_resolver: Arc::new(NoopResolver),
            shutdown: ShutdownSignal::new(),
            state_reads: StateReadHandles::default(),
            modules_config: toml::map::Map::new(),
        }
    }

    #[tokio::test]
    async fn module_with_disallowed_secret_prefix_is_rejected() {
        let module: Arc<dyn ModuleErased> = Arc::new(EmptyModule {
            name: "alpha",
            secrets: vec!["DRIFT_SESSION_SECRET"],
        });
        let registry = ModuleRegistry::load(vec![module], build_test_deps()).await;
        assert_eq!(registry.len(), 1);
        let m = registry.get("alpha").unwrap();
        match &m.status {
            ModuleStatus::Disabled { reason } => {
                assert!(
                    reason.contains("must start with 'MODULE_ALPHA_'"),
                    "expected prefix violation reason, got: {reason}"
                );
            }
            _ => panic!("expected Disabled status, got {:?}", m.status),
        }
    }

    #[tokio::test]
    async fn module_with_allowed_secret_prefix_loads() {
        let module: Arc<dyn ModuleErased> = Arc::new(EmptyModule {
            name: "alpha",
            secrets: vec!["MODULE_ALPHA_API_KEY"],
        });
        let registry = ModuleRegistry::load(vec![module], build_test_deps()).await;
        let m = registry.get("alpha").unwrap();
        assert!(matches!(m.status, ModuleStatus::Running));
    }

    #[tokio::test]
    async fn panicking_init_does_not_crash_registry() {
        let module: Arc<dyn ModuleErased> = Arc::new(PanickingModule);
        let registry = ModuleRegistry::load(vec![module], build_test_deps()).await;
        let m = registry.get("panicking").unwrap();
        match &m.status {
            ModuleStatus::Disabled { reason } => {
                assert!(
                    reason.contains("init panicked"),
                    "expected init panicked reason, got: {reason}"
                );
            }
            _ => panic!("expected Disabled status, got {:?}", m.status),
        }
    }

    #[tokio::test]
    async fn hyphen_in_module_name_normalizes_for_secret_prefix() {
        let module: Arc<dyn ModuleErased> = Arc::new(EmptyModule {
            name: "hello-world",
            secrets: vec!["MODULE_HELLO_WORLD_API_KEY"],
        });
        let registry = ModuleRegistry::load(vec![module], build_test_deps()).await;
        let m = registry.get("hello-world").unwrap();
        assert!(matches!(m.status, ModuleStatus::Running));
    }
}
