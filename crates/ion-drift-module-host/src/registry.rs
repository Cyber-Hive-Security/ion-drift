//! Module registry — validates, initializes, and runs modules.
//!
//! The main entry point is [`ModuleRegistry::load`], which takes a list of
//! modules, constructs contexts, calls `init` on each, collects the returned
//! routers, and exposes a unified Axum `Router` to the host.

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use ion_drift_module_api::context::{
    BoxFuture, EventHandle, MetricsHandle, ModuleConfigHandle, ModuleContext, SecretResolver,
    SecretsHandle, ShutdownSignal, StateReadHandles, TaskSpawner, TaskSupervisorHandle,
};
use ion_drift_module_api::storage::StorageBackend;
use ion_drift_module_api::{
    ApiVersion, Capabilities, Module, ModuleError, ModuleStorage, StorageNeed,
};
use regex::Regex;

use crate::event_bus::EventBus;
use crate::panic_guard::PanicGuardLayer;
use crate::storage_backend::SqliteBackend;

/// Status of a loaded module.
#[derive(Debug, Clone)]
pub enum ModuleStatus {
    /// Initialized successfully and has routes/health/etc.
    Running,
    /// Init failed; module is not active. The string is the human-readable
    /// reason shown in `/api/v1/modules`.
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

            // Build event handle scoped to declared publish/subscribe sets
            let events = deps.event_bus.handle_for(
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
                MetricsHandle::new(),
                deps.shutdown.clone(),
            );

            // Call init inside the module's tracing span
            let init_result = {
                let _entered = span.enter();
                module.init(cx.clone()).await
            };

            match init_result {
                Ok(registration) => {
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
                Err(e) => {
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
    /// `GET /api/v1/modules`.
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

    /// Call shutdown on every running module. Best-effort; errors are
    /// logged but not propagated.
    pub async fn shutdown_all(&self) {
        for m in &self.modules {
            if let (ModuleStatus::Running, Some(cx)) = (&m.status, m.context.as_ref()) {
                let _entered = cx.tracing_span().clone().entered();
                m.module.shutdown(cx).await;
            }
        }
    }
}
