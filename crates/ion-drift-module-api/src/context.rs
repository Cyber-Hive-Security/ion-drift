//! The [`ModuleContext`] passed to modules during init, plus the handles it
//! contains.
//!
//! The context is the module's sole interface to host resources. Modules
//! receive it in [`crate::Module::init`] and capture clones in their spawned
//! tasks. Handles correspond one-to-one to declared [`crate::Capabilities`];
//! undeclared capabilities surface as `None`.
//!
//! These types are trait-object-friendly and reference-counted so modules can
//! freely clone the context into background tasks.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use tokio::sync::broadcast;

use crate::error::{EventError, ModuleError};
use crate::event::{DriftEvent, EventKind};
use crate::state_reads::{
    BehaviorRead, ConnectionRead, DeviceManagerRead, SnapshotRead, StateReadHandleSet,
    SwitchRead,
};
use crate::storage::ModuleStorage;

/// Boxed future used by the handle traits so they are object-safe.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The primary handle a module uses at runtime.
///
/// Cheap to clone: internally reference-counts all the underlying resources.
/// Modules typically clone it into spawned tasks.
#[derive(Clone)]
pub struct ModuleContext {
    name: &'static str,
    tracing_span: tracing::Span,
    config: ModuleConfigHandle,
    storage: Option<ModuleStorage>,
    state: StateReadHandleSet,
    events: EventHandle,
    task_supervisor: TaskSupervisorHandle,
    secrets: SecretsHandle,
    shutdown: ShutdownSignal,
}

impl ModuleContext {
    /// Construct a context. Intended for host use only; modules receive one
    /// from [`crate::Module::init`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &'static str,
        tracing_span: tracing::Span,
        config: ModuleConfigHandle,
        storage: Option<ModuleStorage>,
        state: StateReadHandleSet,
        events: EventHandle,
        task_supervisor: TaskSupervisorHandle,
        secrets: SecretsHandle,
        shutdown: ShutdownSignal,
    ) -> Self {
        Self {
            name,
            tracing_span,
            config,
            storage,
            state,
            events,
            task_supervisor,
            secrets,
            shutdown,
        }
    }

    /// The module's declared name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The pre-scoped tracing span (`module=<name>`).
    pub fn tracing_span(&self) -> &tracing::Span {
        &self.tracing_span
    }

    /// Deserialize the module's TOML config section into a typed value.
    ///
    /// Looks up `[modules.<name>]` from the host config and deserializes to
    /// `T`. Returns `ModuleError::Config` if the section is missing or the
    /// shape is wrong.
    pub fn config<T: DeserializeOwned>(&self) -> Result<T, ModuleError> {
        self.config.load::<T>()
    }

    /// Deserialize the module's TOML config section, falling back to
    /// `Default::default()` if the section is missing.
    ///
    /// **Footgun warning:** if the section is **present but malformed**
    /// (e.g., a typo'd field name, wrong type), this method also returns
    /// the default. This is convenient for genuinely optional config but
    /// will silently mask user errors. Prefer [`Self::config`] for any
    /// module where missing-vs-broken needs to be distinguishable.
    pub fn config_or_default<T: DeserializeOwned + Default>(&self) -> T {
        self.config.load::<T>().unwrap_or_default()
    }

    /// Module's isolated SQLite storage, if [`crate::StorageNeed::Isolated`]
    /// was declared in capabilities.
    pub fn storage(&self) -> Option<&ModuleStorage> {
        self.storage.as_ref()
    }

    /// Read handle to the behavior store, if that state read was declared.
    pub fn behavior(&self) -> Option<&dyn BehaviorRead> {
        self.state.behavior.as_deref()
    }

    /// Read handle to the switch store, if that state read was declared.
    pub fn switch(&self) -> Option<&dyn SwitchRead> {
        self.state.switch.as_deref()
    }

    /// Read handle to the connection store, if that state read was declared.
    pub fn connection(&self) -> Option<&dyn ConnectionRead> {
        self.state.connection.as_deref()
    }

    /// Read handle to the resolved infrastructure snapshot, if declared.
    pub fn snapshot(&self) -> Option<&dyn SnapshotRead> {
        self.state.snapshot.as_deref()
    }

    /// Read handle to the device manager, if declared.
    pub fn devices(&self) -> Option<&dyn DeviceManagerRead> {
        self.state.devices.as_deref()
    }

    /// Publish an event to the bus.
    ///
    /// Returns [`EventError::NotDeclared`] if the event kind was not in the
    /// module's declared publish set. `DriftEvent::ModuleCustom` is rejected
    /// here because its source field would be module-controlled — use
    /// [`Self::publish_custom`] instead.
    pub fn publish(&self, event: DriftEvent) -> Result<(), EventError> {
        self.events.publish(event)
    }

    /// Publish a custom module-to-module event with a host-stamped source.
    ///
    /// The `source` field on the resulting event is set to the module's own
    /// name as known to the host — modules cannot spoof origin.
    pub fn publish_custom(
        &self,
        kind: &'static str,
        payload: serde_json::Value,
    ) -> Result<(), EventError> {
        self.events.publish_custom(kind, payload)
    }

    /// Subscribe to the event bus, receiving only events the module declared.
    ///
    /// Each call returns a fresh receiver; clone the context and call
    /// `subscribe()` in a spawned task for best isolation.
    pub fn subscribe(&self) -> EventReceiver {
        self.events.subscribe()
    }

    /// Spawn a long-lived background task under the host supervisor.
    ///
    /// The task runs inside the module's tracing span. Panics are caught by
    /// the supervisor and restarted with exponential backoff. Because the
    /// supervisor may call the factory multiple times (on restart), `f` must
    /// be `Fn`, not `FnOnce`. The future should honor the [`ShutdownSignal`]
    /// for cooperative shutdown.
    pub fn spawn_task<F, Fut>(&self, name: &str, f: F)
    where
        F: Fn(ModuleContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let cx = self.clone();
        let factory = Arc::new(f);
        self.task_supervisor.spawn(
            name,
            Box::new(move || {
                let cx = cx.clone();
                let f = factory.clone();
                Box::pin(async move { f(cx).await })
            }),
        );
    }

    /// Resolve a named secret. Returns `None` if the secret was not declared
    /// or not found. Secrets are resolved from environment variables by
    /// default; the host may extend this to a keyring.
    pub fn secret(&self, name: &'static str) -> Option<String> {
        self.secrets.resolve(name)
    }

    /// The shutdown signal. Tasks should race their work against
    /// `shutdown.cancelled()` to exit cleanly on host shutdown.
    pub fn shutdown_signal(&self) -> &ShutdownSignal {
        &self.shutdown
    }
}

// ── Handles ──────────────────────────────────────────────────────────

/// Typed config loader for a single module.
///
/// The host constructs this with the raw TOML value for
/// `[modules.<name>]`; the module calls `load::<T>` to deserialize.
#[derive(Clone)]
pub struct ModuleConfigHandle {
    raw: Arc<toml::Value>,
}

impl ModuleConfigHandle {
    pub fn new(raw: toml::Value) -> Self {
        Self { raw: Arc::new(raw) }
    }

    pub fn empty() -> Self {
        Self {
            raw: Arc::new(toml::Value::Table(toml::map::Map::new())),
        }
    }

    pub fn load<T: DeserializeOwned>(&self) -> Result<T, ModuleError> {
        T::deserialize((*self.raw).clone())
            .map_err(|e| ModuleError::Config(e.to_string()))
    }
}

/// Per-kind senders the host hands to an [`EventHandle`].
///
/// Internal type — host code constructs this; module code never touches it.
#[derive(Clone)]
pub struct EventHandleSenders {
    pub publish: Arc<std::collections::HashMap<EventKind, broadcast::Sender<DriftEvent>>>,
    pub subscribe: Arc<std::collections::HashMap<EventKind, broadcast::Sender<DriftEvent>>>,
}

/// Shared shape passed from host to [`EventHandle::from_shared`]. Internal.
#[derive(Clone)]
pub struct EventHandleShared {
    pub module_name: &'static str,
    pub declared_publish: Arc<Vec<EventKind>>,
    pub declared_subscribe: Arc<Vec<EventKind>>,
    pub senders: EventHandleSenders,
}

/// Event bus handle attached to a module context.
///
/// Enforces the module's declared publish set at runtime. The subscribe side
/// is filtered at the receiver wrapper so modules only see events they asked
/// for. The `module_name` is host-populated and used to stamp the `source`
/// field on `DriftEvent::ModuleCustom` events so modules cannot spoof origin.
///
/// Internally, each `EventKind` has its own `tokio::sync::broadcast` channel,
/// so a high-rate topic does not lag a low-rate subscriber. The
/// [`EventReceiver`] returned from [`Self::subscribe`] merges the per-kind
/// channels via a forwarder task and exposes a single `recv()` API.
#[derive(Clone)]
pub struct EventHandle {
    shared: EventHandleShared,
}

impl EventHandle {
    /// Construct an EventHandle from host-supplied internals.
    ///
    /// Intended for host use. Modules receive an EventHandle through their
    /// [`ModuleContext`] and never call this directly.
    pub fn from_shared(shared: EventHandleShared) -> Self {
        Self { shared }
    }

    /// Legacy single-sender constructor — kept for the in-process test
    /// harness which doesn't use the per-kind bus.
    pub fn new(
        sender: broadcast::Sender<DriftEvent>,
        module_name: &'static str,
        declared_publish: Vec<EventKind>,
        declared_subscribe: Vec<EventKind>,
    ) -> Self {
        // The mock context uses a single channel for all kinds. We populate
        // every declared kind with the same sender so publish/subscribe still
        // route through the EventHandleSenders shape.
        let mut publish_map = std::collections::HashMap::new();
        for k in &declared_publish {
            publish_map.insert(*k, sender.clone());
        }
        let mut subscribe_map = std::collections::HashMap::new();
        for k in &declared_subscribe {
            subscribe_map.insert(*k, sender.clone());
        }
        Self {
            shared: EventHandleShared {
                module_name,
                declared_publish: Arc::new(declared_publish),
                declared_subscribe: Arc::new(declared_subscribe),
                senders: EventHandleSenders {
                    publish: Arc::new(publish_map),
                    subscribe: Arc::new(subscribe_map),
                },
            },
        }
    }

    /// Publish a non-`ModuleCustom` event to the bus.
    ///
    /// `ModuleCustom` is rejected here because its `source` field would be
    /// module-controlled, allowing origin spoofing. Use [`Self::publish_custom`]
    /// instead — it stamps the source from the host-known module name.
    pub fn publish(&self, event: DriftEvent) -> Result<(), EventError> {
        let kind = EventKind::of(&event);
        if matches!(kind, EventKind::ModuleCustom) {
            return Err(EventError::CustomMustUsePublishCustom);
        }
        if !self.shared.declared_publish.contains(&kind) {
            return Err(EventError::NotDeclared(kind));
        }
        if let Some(sender) = self.shared.senders.publish.get(&kind) {
            // broadcast::Sender::send returns Err if there are no receivers;
            // that is fine and not a real error — events are advisory.
            let _ = sender.send(event);
        }
        Ok(())
    }

    /// Publish a `ModuleCustom` event with a host-stamped source.
    ///
    /// The `source` field on the resulting event is set to the module's own
    /// name as known to the host — modules cannot spoof another module's name
    /// or claim to be a core engine.
    pub fn publish_custom(
        &self,
        kind: &'static str,
        payload: serde_json::Value,
    ) -> Result<(), EventError> {
        if !self
            .shared
            .declared_publish
            .contains(&EventKind::ModuleCustom)
        {
            return Err(EventError::NotDeclared(EventKind::ModuleCustom));
        }
        let event = DriftEvent::ModuleCustom {
            source: self.shared.module_name,
            kind,
            payload: Arc::new(payload),
        };
        if let Some(sender) = self.shared.senders.publish.get(&EventKind::ModuleCustom) {
            let _ = sender.send(event);
        }
        Ok(())
    }

    /// Subscribe to the bus, receiving only events the module declared.
    ///
    /// Internally spawns a forwarder task per declared subscribe kind that
    /// reads from that kind's broadcast channel and pushes events into a
    /// per-handle mpsc. The forwarder tasks exit when the receiver is
    /// dropped.
    pub fn subscribe(&self) -> EventReceiver {
        let (tx, rx) = tokio::sync::mpsc::channel::<DriftEvent>(64);
        for kind in self.shared.declared_subscribe.iter() {
            let Some(sender) = self.shared.senders.subscribe.get(kind) else {
                continue;
            };
            let mut bcast_rx = sender.subscribe();
            let tx = tx.clone();
            tokio::spawn(async move {
                loop {
                    match bcast_rx.recv().await {
                        Ok(event) => {
                            if tx.send(event).await.is_err() {
                                break; // Receiver dropped — exit forwarder.
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            // Drop the lagged events and continue. The
                            // mpsc receiver will not see Lagged because it
                            // is a separate channel; if a module wants to
                            // detect lag at the per-kind layer, that's a
                            // future enhancement.
                            continue;
                        }
                    }
                }
            });
        }
        drop(tx); // The original sender stays alive in each spawned task only
        EventReceiver {
            inner: rx,
        }
    }
}

/// Receiver for events the module subscribed to. Internally backed by an
/// mpsc fed by per-kind forwarder tasks.
pub struct EventReceiver {
    inner: tokio::sync::mpsc::Receiver<DriftEvent>,
}

impl EventReceiver {
    /// Await the next event matching the module's subscribe set.
    ///
    /// Returns `Err(EventError::Closed)` if all upstream forwarders have
    /// exited (typically because the bus is shutting down).
    pub async fn recv(&mut self) -> Result<DriftEvent, EventError> {
        match self.inner.recv().await {
            Some(event) => Ok(event),
            None => Err(EventError::Closed),
        }
    }
}

/// Opaque handle the context uses to spawn tasks through the host supervisor.
///
/// The concrete factory lives in the host crate; modules see this as a
/// type-erased boxed closure that takes a task name and returns a factory fn.
type TaskFactoryFn = dyn Fn() -> BoxFuture<'static, ()> + Send + Sync + 'static;

#[derive(Clone)]
pub struct TaskSupervisorHandle {
    spawner: Arc<dyn TaskSpawner>,
}

impl TaskSupervisorHandle {
    pub fn new(spawner: Arc<dyn TaskSpawner>) -> Self {
        Self { spawner }
    }

    pub(crate) fn spawn(&self, name: &str, factory: Box<TaskFactoryFn>) {
        self.spawner.spawn(name, factory);
    }
}

/// Abstraction over the host's task supervisor, so the module-api crate
/// doesn't need to depend on `ion-drift-web`.
pub trait TaskSpawner: Send + Sync + 'static {
    fn spawn(&self, name: &str, factory: Box<TaskFactoryFn>);
}

/// Secrets resolver. Modules call `resolve(name)` with a name they declared
/// in [`crate::Capabilities::secrets`].
#[derive(Clone)]
pub struct SecretsHandle {
    declared: Arc<Vec<&'static str>>,
    resolver: Arc<dyn SecretResolver>,
}

impl SecretsHandle {
    pub fn new(declared: Vec<&'static str>, resolver: Arc<dyn SecretResolver>) -> Self {
        Self {
            declared: Arc::new(declared),
            resolver,
        }
    }

    pub fn resolve(&self, name: &'static str) -> Option<String> {
        if !self.declared.contains(&name) {
            return None;
        }
        self.resolver.resolve(name)
    }
}

/// Abstraction over the host's secret provider (env, keyring, etc.).
pub trait SecretResolver: Send + Sync + 'static {
    fn resolve(&self, name: &str) -> Option<String>;
}

/// Cooperative shutdown signal.
///
/// Tasks should race their work against `cancelled()` to exit cleanly when
/// the host is shutting down.
#[derive(Clone)]
pub struct ShutdownSignal {
    inner: Arc<tokio::sync::Notify>,
    flag: Arc<std::sync::atomic::AtomicBool>,
}

impl ShutdownSignal {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(tokio::sync::Notify::new()),
            flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Returns true if shutdown has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Wait until shutdown is requested.
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        self.inner.notified().await;
    }

    /// Signal shutdown. Intended for host use.
    pub fn cancel(&self) {
        self.flag.store(true, std::sync::atomic::Ordering::Release);
        self.inner.notify_waiters();
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// Bundle of state read handles, re-exported for convenience under a
/// shorter name.
pub type StateReadHandles = StateReadHandleSet;
