//! Test harness for unit-testing modules in isolation.
//!
//! Gated behind `#[cfg(any(test, feature = "testing"))]`. Modules that want
//! to unit-test without spinning up a real Drift instance enable the
//! `testing` feature on `ion-drift-module-api`:
//!
//! ```toml
//! [dev-dependencies]
//! ion-drift-module-api = { workspace = true, features = ["testing"] }
//! ```
//!
//! Then in tests:
//!
//! ```rust,ignore
//! use ion_drift_module_api::testing::MockContextBuilder;
//!
//! #[tokio::test]
//! async fn my_module_inits_cleanly() {
//!     let cx = MockContextBuilder::new("my-module").build();
//!     // ... construct module, call init, assert behavior
//! }
//! ```

use std::sync::Arc;

use tokio::sync::broadcast;

use crate::context::{
    EventHandle, MetricsHandle, ModuleConfigHandle, ModuleContext, SecretResolver,
    SecretsHandle, ShutdownSignal, TaskSpawner, TaskSupervisorHandle,
};
use crate::event::{DriftEvent, EventKind};
use crate::state_reads::StateReadHandleSet;

/// Builder for a mock [`ModuleContext`] suitable for unit tests.
pub struct MockContextBuilder {
    name: &'static str,
    config: Option<toml::Value>,
    declared_publish: Vec<EventKind>,
    declared_subscribe: Vec<EventKind>,
    state: StateReadHandleSet,
    secrets: std::collections::HashMap<String, String>,
}

impl MockContextBuilder {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            config: None,
            declared_publish: Vec::new(),
            declared_subscribe: Vec::new(),
            state: StateReadHandleSet::default(),
            secrets: std::collections::HashMap::new(),
        }
    }

    pub fn with_config(mut self, config: toml::Value) -> Self {
        self.config = Some(config);
        self
    }

    pub fn with_publish(mut self, kinds: Vec<EventKind>) -> Self {
        self.declared_publish = kinds;
        self
    }

    pub fn with_subscribe(mut self, kinds: Vec<EventKind>) -> Self {
        self.declared_subscribe = kinds;
        self
    }

    pub fn with_secret(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.secrets.insert(name.into(), value.into());
        self
    }

    pub fn build(self) -> (ModuleContext, MockHandles) {
        let (sender, _unused_receiver) = broadcast::channel::<DriftEvent>(64);
        let config = self
            .config
            .map(ModuleConfigHandle::new)
            .unwrap_or_else(ModuleConfigHandle::empty);

        let events = EventHandle::new(
            sender.clone(),
            self.declared_publish.clone(),
            self.declared_subscribe.clone(),
        );

        let task_spawner: Arc<dyn TaskSpawner> = Arc::new(MockTaskSpawner::new());
        let task_handle = TaskSupervisorHandle::new(task_spawner.clone());

        let secret_resolver: Arc<dyn SecretResolver> =
            Arc::new(MockSecretResolver::new(self.secrets));
        let declared_secret_names: Vec<&'static str> = Vec::new();
        let secrets = SecretsHandle::new(declared_secret_names, secret_resolver);

        let shutdown = ShutdownSignal::new();

        let span = tracing::info_span!("module", name = %self.name);
        let cx = ModuleContext::new(
            self.name,
            span,
            config,
            None,
            self.state,
            events,
            task_handle,
            secrets,
            MetricsHandle::new(),
            shutdown,
        );

        let handles = MockHandles {
            event_sender: sender,
        };

        (cx, handles)
    }
}

/// Inspectable handles returned alongside the mock context. Tests use these
/// to inject events or observe side effects.
pub struct MockHandles {
    pub event_sender: broadcast::Sender<DriftEvent>,
}

impl MockHandles {
    /// Inject an event into the bus so a subscribed module sees it.
    pub fn inject(&self, event: DriftEvent) {
        let _ = self.event_sender.send(event);
    }
}

// ── Mock backends ────────────────────────────────────────────────────

struct MockTaskSpawner {
    // In a real test you might want to capture spawned tasks for
    // inspection. For v1.0 we just drop them (no-op).
}

impl MockTaskSpawner {
    fn new() -> Self {
        Self {}
    }
}

impl TaskSpawner for MockTaskSpawner {
    fn spawn(
        &self,
        _name: &str,
        _factory: Box<
            dyn Fn() -> crate::context::BoxFuture<'static, ()> + Send + Sync + 'static,
        >,
    ) {
        // Mock: no-op. Tests that need to verify task spawning can use a
        // custom TaskSpawner.
    }
}

struct MockSecretResolver {
    secrets: std::collections::HashMap<String, String>,
}

impl MockSecretResolver {
    fn new(secrets: std::collections::HashMap<String, String>) -> Self {
        Self { secrets }
    }
}

impl SecretResolver for MockSecretResolver {
    fn resolve(&self, name: &str) -> Option<String> {
        self.secrets.get(name).cloned()
    }
}
