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
//!     let (cx, _handles) = MockContextBuilder::new("my-module").build();
//!     // ... construct module, call init, assert behavior
//! }
//! ```

use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

use crate::context::{
    BoxFuture, EventHandle, ModuleConfigHandle, ModuleContext, SecretResolver, SecretsHandle,
    ShutdownSignal, TaskSpawner, TaskSupervisorHandle,
};
use crate::event::{DriftEvent, EventKind};
use crate::state_reads::{
    AnomalyRef, BehaviorBaselineRef, BehaviorRead, ConnectionRead, ConnectionRef, DeviceManagerRead,
    DeviceRef, MacLocationRef, SnapshotNodeRef, SnapshotRead, StateReadHandleSet, SwitchRead,
};

/// Builder for a mock [`ModuleContext`] suitable for unit tests.
pub struct MockContextBuilder {
    name: &'static str,
    config: Option<toml::Value>,
    declared_publish: Vec<EventKind>,
    declared_subscribe: Vec<EventKind>,
    state: StateReadHandleSet,
    /// Vec of (declared_name, value) pairs. The name MUST be `&'static str`
    /// because `SecretsHandle::declared` requires that lifetime.
    secrets: Vec<(&'static str, String)>,
}

impl MockContextBuilder {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            config: None,
            declared_publish: Vec::new(),
            declared_subscribe: Vec::new(),
            state: StateReadHandleSet::default(),
            secrets: Vec::new(),
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

    /// Declare and provide a value for a named secret. The same name passed
    /// here is what `cx.secret(name)` will resolve.
    pub fn with_secret(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.secrets.push((name, value.into()));
        self
    }

    /// Attach a behavior-store mock. The state_reads.behavior capability is
    /// implicitly granted.
    pub fn with_behavior_read(mut self, mock: Arc<dyn BehaviorRead>) -> Self {
        self.state.behavior = Some(mock);
        self
    }

    /// Attach a switch-store mock.
    pub fn with_switch_read(mut self, mock: Arc<dyn SwitchRead>) -> Self {
        self.state.switch = Some(mock);
        self
    }

    /// Attach a connection-store mock.
    pub fn with_connection_read(mut self, mock: Arc<dyn ConnectionRead>) -> Self {
        self.state.connection = Some(mock);
        self
    }

    /// Attach a snapshot mock.
    pub fn with_snapshot_read(mut self, mock: Arc<dyn SnapshotRead>) -> Self {
        self.state.snapshot = Some(mock);
        self
    }

    /// Attach a device-manager mock.
    pub fn with_device_manager_read(mut self, mock: Arc<dyn DeviceManagerRead>) -> Self {
        self.state.devices = Some(mock);
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
            self.name,
            self.declared_publish.clone(),
            self.declared_subscribe.clone(),
        );

        let task_spawner: Arc<dyn TaskSpawner> = Arc::new(MockTaskSpawner::new());
        let task_handle = TaskSupervisorHandle::new(task_spawner.clone());

        // Both the declared name list and the underlying resolver get the
        // same set of secrets — fixes the prior bug where with_secret
        // populated the resolver but never declared the name.
        let declared_names: Vec<&'static str> = self.secrets.iter().map(|(n, _)| *n).collect();
        let resolver_map: std::collections::HashMap<String, String> = self
            .secrets
            .into_iter()
            .map(|(n, v)| (n.to_string(), v))
            .collect();
        let secret_resolver: Arc<dyn SecretResolver> =
            Arc::new(MockSecretResolver::new(resolver_map));
        let secrets = SecretsHandle::new(declared_names, secret_resolver);

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

struct MockTaskSpawner;

impl MockTaskSpawner {
    fn new() -> Self {
        Self
    }
}

impl TaskSpawner for MockTaskSpawner {
    fn spawn(
        &self,
        _name: &str,
        _factory: Box<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync + 'static>,
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

// ── Mock state-read implementations ──────────────────────────────────
//
// Module authors use these to construct unit tests without implementing the
// read traits themselves. Each mock holds a `Mutex` of canned data so the
// trait objects are `Send + Sync` as required.

/// Mock implementation of [`BehaviorRead`] backed by canned data.
#[derive(Default)]
pub struct MockBehaviorRead {
    inner: Mutex<MockBehaviorReadInner>,
}

#[derive(Default)]
struct MockBehaviorReadInner {
    baselines: std::collections::HashMap<String, BehaviorBaselineRef>,
    anomalies: Vec<AnomalyRef>,
}

impl MockBehaviorRead {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_baseline(self, baseline: BehaviorBaselineRef) -> Self {
        self.inner
            .lock()
            .expect("mock behavior poisoned")
            .baselines
            .insert(baseline.device_mac.clone(), baseline);
        self
    }

    pub fn with_anomaly(self, anomaly: AnomalyRef) -> Self {
        self.inner
            .lock()
            .expect("mock behavior poisoned")
            .anomalies
            .push(anomaly);
        self
    }
}

impl BehaviorRead for MockBehaviorRead {
    fn get_baseline<'a>(
        &'a self,
        device_mac: &'a str,
    ) -> BoxFuture<'a, Option<BehaviorBaselineRef>> {
        Box::pin(async move {
            self.inner
                .lock()
                .ok()?
                .baselines
                .get(device_mac)
                .cloned()
        })
    }

    fn recent_anomalies<'a>(
        &'a self,
        since_unix: i64,
        limit: usize,
    ) -> BoxFuture<'a, Vec<AnomalyRef>> {
        Box::pin(async move {
            let inner = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return Vec::new(),
            };
            inner
                .anomalies
                .iter()
                .filter(|a| a.timestamp_unix >= since_unix)
                .take(limit)
                .cloned()
                .collect()
        })
    }
}

/// Mock implementation of [`SwitchRead`] backed by canned data.
#[derive(Default)]
pub struct MockSwitchRead {
    inner: Mutex<MockSwitchReadInner>,
}

#[derive(Default)]
struct MockSwitchReadInner {
    locations: std::collections::HashMap<String, MacLocationRef>,
    devices: Vec<String>,
}

impl MockSwitchRead {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_mac_location(self, location: MacLocationRef) -> Self {
        self.inner
            .lock()
            .expect("mock switch poisoned")
            .locations
            .insert(location.mac.clone(), location);
        self
    }

    pub fn with_device_id(self, id: impl Into<String>) -> Self {
        self.inner
            .lock()
            .expect("mock switch poisoned")
            .devices
            .push(id.into());
        self
    }
}

impl SwitchRead for MockSwitchRead {
    fn locate_mac<'a>(&'a self, mac: &'a str) -> BoxFuture<'a, Option<MacLocationRef>> {
        Box::pin(async move {
            self.inner.lock().ok()?.locations.get(mac).cloned()
        })
    }

    fn device_ids<'a>(&'a self) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move {
            self.inner
                .lock()
                .map(|g| g.devices.clone())
                .unwrap_or_default()
        })
    }
}

/// Mock implementation of [`ConnectionRead`] backed by canned data.
#[derive(Default)]
pub struct MockConnectionRead {
    inner: Mutex<Vec<ConnectionRef>>,
}

impl MockConnectionRead {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_connection(self, conn: ConnectionRef) -> Self {
        self.inner
            .lock()
            .expect("mock connection poisoned")
            .push(conn);
        self
    }
}

impl ConnectionRead for MockConnectionRead {
    fn for_device<'a>(
        &'a self,
        device_mac: &'a str,
        limit: usize,
    ) -> BoxFuture<'a, Vec<ConnectionRef>> {
        Box::pin(async move {
            let inner = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return Vec::new(),
            };
            inner
                .iter()
                .filter(|c| c.src_mac.as_deref() == Some(device_mac))
                .take(limit)
                .cloned()
                .collect()
        })
    }
}

/// Mock implementation of [`SnapshotRead`] backed by canned data.
#[derive(Default)]
pub struct MockSnapshotRead {
    inner: Mutex<MockSnapshotReadInner>,
}

#[derive(Default)]
struct MockSnapshotReadInner {
    generation: u64,
    nodes: Vec<SnapshotNodeRef>,
}

impl MockSnapshotRead {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_generation(self, generation: u64) -> Self {
        self.inner.lock().expect("mock snapshot poisoned").generation = generation;
        self
    }

    pub fn with_node(self, node: SnapshotNodeRef) -> Self {
        self.inner
            .lock()
            .expect("mock snapshot poisoned")
            .nodes
            .push(node);
        self
    }
}

impl SnapshotRead for MockSnapshotRead {
    fn generation<'a>(&'a self) -> BoxFuture<'a, u64> {
        Box::pin(async move { self.inner.lock().map(|g| g.generation).unwrap_or(0) })
    }

    fn nodes<'a>(&'a self) -> BoxFuture<'a, Vec<SnapshotNodeRef>> {
        Box::pin(async move {
            self.inner
                .lock()
                .map(|g| g.nodes.clone())
                .unwrap_or_default()
        })
    }
}

/// Mock implementation of [`DeviceManagerRead`] backed by canned data.
#[derive(Default)]
pub struct MockDeviceManagerRead {
    inner: Mutex<Vec<DeviceRef>>,
}

impl MockDeviceManagerRead {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_device(self, device: DeviceRef) -> Self {
        self.inner
            .lock()
            .expect("mock device manager poisoned")
            .push(device);
        self
    }
}

impl DeviceManagerRead for MockDeviceManagerRead {
    fn list<'a>(&'a self) -> BoxFuture<'a, Vec<DeviceRef>> {
        Box::pin(async move {
            self.inner
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default()
        })
    }

    fn get<'a>(&'a self, device_id: &'a str) -> BoxFuture<'a, Option<DeviceRef>> {
        Box::pin(async move {
            self.inner
                .lock()
                .ok()?
                .iter()
                .find(|d| d.id == device_id)
                .cloned()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn with_secret_round_trips() {
        let (cx, _handles) = MockContextBuilder::new("alpha")
            .with_secret("ALPHA_API_KEY", "secret-value")
            .build();
        assert_eq!(cx.secret("ALPHA_API_KEY"), Some("secret-value".to_string()));
        // Undeclared secret name returns None
        assert_eq!(cx.secret("OTHER"), None);
    }

    #[tokio::test]
    async fn mock_behavior_read_round_trips() {
        let mock = MockBehaviorRead::new().with_baseline(BehaviorBaselineRef {
            device_mac: "aa:bb:cc:dd:ee:ff".into(),
            status: "baselined".into(),
            observation_count: 5000,
            learning_until_unix: 0,
        });
        let (cx, _handles) = MockContextBuilder::new("alpha")
            .with_behavior_read(Arc::new(mock))
            .build();
        let handle = cx.behavior().expect("behavior read should be wired");
        let baseline = handle.get_baseline("aa:bb:cc:dd:ee:ff").await;
        assert!(baseline.is_some());
        assert_eq!(baseline.unwrap().status, "baselined");
    }

    #[tokio::test]
    async fn module_custom_source_is_host_stamped() {
        let (cx, _handles) = MockContextBuilder::new("alpha")
            .with_publish(vec![EventKind::ModuleCustom])
            .with_subscribe(vec![EventKind::ModuleCustom])
            .build();

        // Subscribe BEFORE publishing so the broadcast slot is held.
        let mut rx = cx.subscribe();

        // Module publishes via the public API; source is host-stamped.
        cx.publish_custom("hello", serde_json::json!({"k": "v"}))
            .unwrap();

        let received = rx.recv().await.expect("event");
        match received {
            DriftEvent::ModuleCustom { source, kind, .. } => {
                assert_eq!(source, "alpha");
                assert_eq!(kind, "hello");
            }
            other => panic!("expected ModuleCustom, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn plain_publish_rejects_module_custom() {
        let (cx, _handles) = MockContextBuilder::new("alpha")
            .with_publish(vec![EventKind::ModuleCustom])
            .build();

        // Even an attempt to publish a ModuleCustom via the plain `publish`
        // API must fail — modules can't bypass host stamping by hand-rolling
        // the variant.
        let attempt = cx.publish(DriftEvent::ModuleCustom {
            source: "behavior_engine", // spoofed
            kind: "anything",
            payload: std::sync::Arc::new(serde_json::Value::Null),
        });
        assert!(matches!(
            attempt,
            Err(crate::EventError::CustomMustUsePublishCustom)
        ));
    }
}
