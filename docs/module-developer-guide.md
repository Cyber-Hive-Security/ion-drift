# Ion Drift Module Developer Guide

This guide walks through writing a module for Ion Drift. Modules are
self-contained extensions that plug into Drift via a stable API contract,
without modifying Drift core. They can register HTTP routes, spawn
background tasks, read core state through narrow read-only handles,
publish and subscribe to events, and own isolated SQLite storage.

This guide covers the v1.0 contract. The API is stable across the 1.x
series — additive minor bumps only.

---

## Table of contents

1. [What modules are](#what-modules-are)
2. [What modules are NOT](#what-modules-are-not)
3. [Crate setup](#crate-setup)
4. [The Module trait](#the-module-trait)
5. [Capabilities](#capabilities)
6. [The ModuleContext](#the-modulecontext)
7. [Storage](#storage)
8. [Events](#events)
9. [State reads](#state-reads)
10. [Secrets](#secrets)
11. [Background tasks](#background-tasks)
12. [Configuration](#configuration)
13. [Lifecycle](#lifecycle)
14. [Testing](#testing)
15. [A complete hello-world module](#a-complete-hello-world-module)
16. [Composing your module into a Drift build](#composing-your-module-into-a-drift-build)
17. [Stability and versioning](#stability-and-versioning)
18. [Known limitations in v1.0](#known-limitations-in-v10)

---

## What modules are

A module is a Rust type that implements the `Module` trait from
`ion-drift-module-api`. The module is loaded into Drift at startup via an
explicit list, and the host gives it a `ModuleContext` containing exactly
the resources it declared in its `Capabilities`. Anything the module did
not declare is absent from the context — the boundary is enforced at the
handle layer, not by hard sandboxing.

Concretely, a module can:

- Register an HTTP router that gets mounted at `/api/modules/<module-name>/`
- Spawn long-lived background tasks under the host's task supervisor (with
  panic catching and exponential-backoff restart)
- Read from core Drift state through narrow trait objects (currently
  `BehaviorRead` and `SwitchRead`; more in future minor bumps)
- Publish and subscribe to typed events on the per-kind event bus
- Own an isolated SQLite database at `${data_dir}/modules/<name>.db`
- Resolve named secrets scoped to its own namespace (`MODULE_<NAME>_*`)
- Receive its own TOML config section from `[modules.<name>]`
- Cooperatively shut down when the host receives SIGTERM

## What modules are NOT

- Not a hard sandbox. Modules run in the same process as Drift core. The
  capability handles protect against accident and misconfiguration, not
  against modules that genuinely want to break out (e.g. via `unsafe`,
  filesystem APIs, or network calls).
- Not allowed to mutate core state. The state read traits expose query
  methods only — there's no way to write to the behavior store, switch
  store, etc. through the trait objects. This is enforced by the Rust
  type system: the traits literally have no mutation methods.
- Not allowed to modify Drift's router outside their own prefix. Routes
  registered by a module are nested at `/api/modules/<name>/`; the host
  does not honor any route the module's `Router` declares outside its
  prefix.
- Not loaded dynamically at runtime. The module list is a `Vec<Arc<dyn
  Module>>` constructed at compile time in the host binary. There is no
  `dlopen`-style loading.
- Not crates.io published in v1.0. The `ion-drift-module-api` crate is
  consumed via path or git dependency only.

---

## Crate setup

A module is a Rust library crate (or part of one) that depends on
`ion-drift-module-api`. The host crate provides the runtime; you only
depend on the API contract.

```toml
# my-module/Cargo.toml
[package]
name = "my-module"
version = "0.1.0"
edition = "2024"

[dependencies]
ion-drift-module-api = { path = "../ion-drift/crates/ion-drift-module-api" }
# Or via git:
# ion-drift-module-api = { git = "https://github.com/...", tag = "ion-drift-module-api-v1.0.0" }

# Common companions
async-trait = "0.1"     # Optional — only if you need it. The Module trait does not.
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["sync"] }
tracing = "0.1"
axum = "0.8"            # Only if you register HTTP routes.
rusqlite = { version = "0.32", features = ["bundled"] }  # Only if you use isolated storage.

[dev-dependencies]
ion-drift-module-api = { path = "...", features = ["testing"] }
tokio = { version = "1", features = ["macros", "rt"] }
```

The `testing` feature on `ion-drift-module-api` exposes `MockContextBuilder`
and the various `Mock*Read` types for unit tests. It is gated so the test
harness does not pollute production builds.

---

## The Module trait

The whole contract is a single trait. Native `async fn` is used (Rust
1.75+); no `async-trait` crate is needed for the trait itself.

```rust
use ion_drift_module_api::*;

pub struct MyModule;

impl Module for MyModule {
    fn name(&self) -> &'static str { "my-module" }
    fn version(&self) -> &'static str { env!("CARGO_PKG_VERSION") }

    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }

    async fn init(
        &self,
        _cx: ModuleContext,
    ) -> Result<ModuleRegistration, ModuleError> {
        Ok(ModuleRegistration::default())
    }
}
```

That's a complete (but useless) module. The `name()` is the module's
identity used for routing, storage file naming, secret namespace, and the
`/api/system/modules` listing. It must match `^[a-z][a-z0-9_-]{1,31}$` —
lowercase letters, digits, hyphens and underscores, starting with a letter,
length 2–32. Modules with invalid names are marked `Disabled` at
registration time and skipped (the host does not panic).

`version()` is the module's own semver, typically `env!("CARGO_PKG_VERSION")`.
It's used for diagnostics and the `/api/system/modules` listing.

`api_version()` defaults to `ApiVersion::CURRENT` of the
`ion-drift-module-api` crate the module was built against. The host
verifies compatibility at startup and rejects modules whose major version
differs or whose minor version exceeds the host's. You should not override
this unless you have a very specific reason.

---

## Capabilities

The `Capabilities` struct declares what the module needs from the host. The
host then builds a `ModuleContext` containing exactly those handles —
nothing more.

```rust
fn capabilities(&self) -> Capabilities {
    Capabilities {
        storage: StorageNeed::Isolated,
        events: EventSubscriptions {
            subscribe: vec![EventKind::AnomalyDetected],
            publish: vec![EventKind::ModuleCustom],
        },
        state_reads: StateReads {
            behavior: true,
            switch: true,
            ..Default::default()
        },
        secrets: vec!["MODULE_MY_MODULE_API_KEY"],
    }
}
```

Field by field:

- **`storage: StorageNeed`** — `None` (no SQLite file) or `Isolated` (gets
  its own `${data_dir}/modules/<name>.db`).
- **`events.subscribe: Vec<EventKind>`** — kinds the module wants to
  receive. The host filters at the receiver layer; events outside this set
  are not delivered.
- **`events.publish: Vec<EventKind>`** — kinds the module is allowed to
  publish. Attempts to publish other kinds return `EventError::NotDeclared`.
- **`state_reads.behavior` / `.switch` / etc.** — boolean flags for each
  read trait. Only declared reads are exposed via `cx.behavior()` etc.;
  the rest return `None`.
- **`secrets: Vec<&'static str>`** — named secrets the module wants to
  resolve. **Names MUST start with `MODULE_<UPPER_NAME>_`** where
  `UPPER_NAME` is the module's `name()` with hyphens converted to
  underscores and uppercased. Modules declaring secret names outside this
  prefix are marked `Disabled` at registration. Example: a module named
  `hello-world` may declare `secrets: vec!["MODULE_HELLO_WORLD_API_KEY"]`.

There are no separate flags for `routes`, `tasks`, `health`, or `metrics`
— each of those is observable directly (a router is in `ModuleRegistration`,
a task is spawned via `cx.spawn_task`).

---

## The ModuleContext

`ModuleContext` is the runtime handle the module receives from `init` and
clones into its tasks. It exposes only the capabilities the module
declared. It is `Clone` and reference-counted internally — clone freely
into spawned tasks.

Key methods:

| Method | Returns | Notes |
|---|---|---|
| `cx.name()` | `&'static str` | The module's name |
| `cx.tracing_span()` | `&tracing::Span` | Pre-scoped span (`module=<name>`) |
| `cx.config::<T>()` | `Result<T, ModuleError>` | Strict TOML deserialize from `[modules.<name>]` |
| `cx.config_or_default::<T>()` | `T` | Lenient: missing OR malformed config → `T::default()` |
| `cx.storage()` | `Option<&ModuleStorage>` | `Some` only if `StorageNeed::Isolated` declared |
| `cx.behavior()` | `Option<&dyn BehaviorRead>` | `Some` only if `state_reads.behavior` declared |
| `cx.switch()` | `Option<&dyn SwitchRead>` | `Some` only if `state_reads.switch` declared |
| `cx.connection()` | `Option<&dyn ConnectionRead>` | v1.0 stub — returns `None` even if declared |
| `cx.snapshot()` | `Option<&dyn SnapshotRead>` | v1.0 stub — returns `None` even if declared |
| `cx.devices()` | `Option<&dyn DeviceManagerRead>` | v1.0 stub — returns `None` even if declared |
| `cx.publish(event)` | `Result<(), EventError>` | Publish a non-`ModuleCustom` event |
| `cx.publish_custom(kind, payload)` | `Result<(), EventError>` | Publish a `ModuleCustom` with host-stamped source |
| `cx.subscribe()` | `EventReceiver` | Get a receiver for declared subscriptions |
| `cx.secret(name)` | `Option<String>` | Resolve a declared secret |
| `cx.spawn_task(name, factory)` | `()` | Spawn a supervised background task |
| `cx.shutdown_signal()` | `&ShutdownSignal` | Cooperative shutdown signal |

---

## Storage

Modules that declare `StorageNeed::Isolated` get a `ModuleStorage` handle
to a SQLite database at `${data_dir}/modules/<name>.db`. Drift core has
no knowledge of the file or its schema; you own it entirely.

```rust
use ion_drift_module_api::storage::Migration;

const MIGRATIONS: &[Migration] = &[
    Migration {
        name: "0001_create_events",
        sql: "CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at INTEGER NOT NULL
              );",
    },
];

async fn init(&self, cx: ModuleContext) -> Result<ModuleRegistration, ModuleError> {
    let storage = cx.storage().ok_or_else(|| {
        ModuleError::CapabilityMissing("storage")
    })?;
    storage.run_migrations(MIGRATIONS).await?;

    let count: i64 = storage
        .write(|conn| {
            conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
                .map_err(|e| ion_drift_module_api::StorageError::Sqlite(e.to_string()))
        })
        .await?;
    tracing::info!(count, "module storage initialized");
    Ok(ModuleRegistration::default())
}
```

`ModuleStorage::write` runs the closure on `tokio::task::spawn_blocking`
under a `std::sync::Mutex<rusqlite::Connection>`. Long queries do NOT
stall the runtime worker threads. Migrations are tracked by name in a
`__migrations` metadata table; re-running an already-applied migration is
a no-op.

---

## Events

Drift publishes a typed `DriftEvent` enum at meaningful lifecycle points
(anomaly detected, investigation completed, snapshot updated, etc.).
Modules subscribe to the kinds they care about and react accordingly.

### Subscribing

```rust
async fn init(&self, cx: ModuleContext) -> Result<ModuleRegistration, ModuleError> {
    let cx_for_task = cx.clone();
    cx.spawn_task("anomaly-listener", move |task_cx| {
        let mut rx = task_cx.subscribe();
        async move {
            loop {
                tokio::select! {
                    _ = task_cx.shutdown_signal().cancelled() => break,
                    event = rx.recv() => match event {
                        Ok(DriftEvent::AnomalyDetected(payload)) => {
                            tracing::info!(
                                anomaly_id = payload.anomaly_id,
                                "module saw anomaly"
                            );
                            // ... do something
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            }
        }
    });
    Ok(ModuleRegistration::default())
}
```

The receiver is filtered by the module's declared subscribe set. Events
outside the set are not delivered to this receiver. Internally, each
declared kind has its own broadcast channel and the host runs forwarder
tasks that funnel them into the receiver's mpsc — so a high-rate topic
(e.g., `ConnectionStateChanged`) will not lag a low-rate subscriber.

### Lag handling

In v1.0, broadcast lag at the per-kind channel boundary is **silently
dropped** by the forwarder task. Modules do NOT see `EventError::Lagged`
from `recv()`. Treat the event stream as best-effort and reconcile state
from authoritative stores (via `cx.behavior()` etc.) on a periodic timer
if your module is sensitive to missed events. A future minor bump may
expose per-kind lag through diagnostic counters.

### Publishing

Plain `DriftEvent` variants:

```rust
cx.publish(DriftEvent::AnomalyDetected(AnomalyDetectedV1 {
    anomaly_id: 1,
    device_mac: "aa:bb:cc:dd:ee:ff".to_string(),
    severity: "critical".to_string(),
    anomaly_type: "test".to_string(),
    vlan: Some(25),
    timestamp_unix: 0,
}))?;
```

`DriftEvent::ModuleCustom` is the escape hatch for module-to-module
communication without changing the core enum. Its `source` field is
**always host-populated** with the publishing module's name — modules
cannot spoof origin. Use `publish_custom`, not the plain `publish`:

```rust
cx.publish_custom(
    "alert-fired",
    serde_json::json!({"device": "aa:bb:cc:dd:ee:ff", "kind": "ddos"}),
)?;
```

The plain `publish` rejects `ModuleCustom` with
`EventError::CustomMustUsePublishCustom` for exactly this reason.

---

## State reads

Modules can read core Drift state through narrow trait objects. The traits
have NO mutation methods — modules cannot accidentally or intentionally
write to Drift's stores through these handles.

Wired in v1.0:

- **`BehaviorRead`** — `get_baseline(mac)`, `recent_anomalies(since, limit)`
- **`SwitchRead`** — `locate_mac(mac)`, `device_ids()`

Stubs in v1.0 (the trait exists but the host returns `None`):

- `ConnectionRead`
- `SnapshotRead`
- `DeviceManagerRead`

These will be wired in future minor bumps. For now, modules that need
connection / snapshot / device-manager data should reach into the
authoritative stores via their own host-built integration (which is not
stable across Drift versions).

```rust
async fn init(&self, cx: ModuleContext) -> Result<ModuleRegistration, ModuleError> {
    if let Some(behavior) = cx.behavior() {
        if let Some(baseline) = behavior.get_baseline("aa:bb:cc:dd:ee:ff").await {
            tracing::info!(?baseline, "got behavior baseline");
        }
    }
    Ok(ModuleRegistration::default())
}
```

---

## Secrets

Modules that need access to external credentials (API keys, tokens, etc.)
declare them in `Capabilities::secrets`. The host resolves them via
environment variables by default.

**Names MUST start with `MODULE_<UPPER_NAME>_`** where `UPPER_NAME` is the
module's name with hyphens converted to underscores, uppercased. This
prevents modules from declaring secret names belonging to Drift core
(`DRIFT_SESSION_SECRET`, etc.) and reading them.

```rust
fn capabilities(&self) -> Capabilities {
    Capabilities {
        secrets: vec!["MODULE_MY_MODULE_API_KEY"],
        ..Default::default()
    }
}

async fn init(&self, cx: ModuleContext) -> Result<ModuleRegistration, ModuleError> {
    let api_key = cx.secret("MODULE_MY_MODULE_API_KEY")
        .ok_or_else(|| ModuleError::Init("API key not set".into()))?;
    // ... use the key
    Ok(ModuleRegistration::default())
}
```

If the operator sets `MODULE_MY_MODULE_API_KEY=...` in the environment,
`cx.secret()` returns it. If the secret name is not in the declared list
or the environment variable is not set, it returns `None`.

---

## Background tasks

`cx.spawn_task` is available to every module — there is no separate
capability flag for it. Tasks run under Drift's task supervisor with
panic catching and exponential-backoff restart. The factory must be `Fn`
(not `FnOnce`) because the supervisor may call it multiple times to
restart a panicking task.

```rust
cx.spawn_task("periodic-sync", |task_cx| async move {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = task_cx.shutdown_signal().cancelled() => break,
            _ = interval.tick() => {
                tracing::info!("periodic sync tick");
                // ... do the work
            }
        }
    }
});
```

Always race the work against `shutdown_signal().cancelled()` so the task
exits cleanly when the host shuts down.

---

## Configuration

Modules receive their TOML config section from the host. Each module
declares its config struct with `serde::Deserialize` and reads it via
`cx.config::<T>()`.

```toml
# Drift's config TOML
[modules.my_module]
enabled = true
sync_interval_seconds = 300
remote_url = "https://example.com/api"
```

```rust
#[derive(Debug, Clone, serde::Deserialize, Default)]
struct MyConfig {
    sync_interval_seconds: u64,
    remote_url: String,
}

async fn init(&self, cx: ModuleContext) -> Result<ModuleRegistration, ModuleError> {
    let config: MyConfig = cx.config()?;
    tracing::info!(?config, "module configured");
    Ok(ModuleRegistration::default())
}
```

`cx.config::<T>()` is **strict**: missing or malformed sections return
`ModuleError::Config`. `cx.config_or_default::<T>()` is **lenient**: both
missing and malformed sections fall back to `T::default()`. Prefer
`cx.config()` unless you genuinely want silent fallback — `_or_default`
is a footgun for typo'd field names.

The convention `enabled = false` in the module's config section disables
the module at startup even if it's compiled in. Modules don't have to
implement this themselves — the host honors it before calling `init`.

---

## Lifecycle

Module lifecycle (executed by `ModuleRegistry` in the host):

1. **Declared** — the host's `modules::load()` returns a
   `Vec<Arc<dyn Module>>` containing your module.
2. **Validated** — the host checks: name regex, uniqueness, API version
   compatibility, secret namespace prefix. Failures mark the module
   `Disabled` and continue with other modules.
3. **Context built** — the host constructs a `ModuleContext` with only the
   capabilities your module declared.
4. **Init called** — `module.init(cx).await` runs inside a `tracing::Span`
   named `module.<name>`. **Errors and panics are caught** at this layer
   and mark the module `Disabled`. They do NOT crash Drift.
5. **Routes mounted** — the returned `ModuleRegistration::router` is
   nested at `/api/modules/<name>/` and wrapped in a tower-layer panic
   guard so a panic in any handler returns HTTP 500 instead of crashing
   the Axum listener.
6. **Tasks running** — any tasks spawned via `cx.spawn_task` execute under
   the task supervisor (panic-catching, exponential backoff).
7. **Shutdown** — on SIGTERM or ctrl-c, the host calls
   `module_shutdown.cancel()` and then `module.shutdown(&cx).await` on
   each running module with a 5-second bounded timeout. Panics here are
   also caught.

`Module::shutdown` is optional and defaults to a no-op. Override it if you
need to flush state, close connections, etc. Always race long-running
shutdown work against the timeout — if your module doesn't return in 5s,
the host moves on without it.

---

## Testing

The `ion-drift-module-api` crate ships a `testing` module behind a feature
flag. Module authors enable it as a dev-dependency and use
`MockContextBuilder` to construct a fake `ModuleContext` for unit tests.

```toml
[dev-dependencies]
ion-drift-module-api = { path = "...", features = ["testing"] }
```

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ion_drift_module_api::testing::*;

    #[tokio::test]
    async fn module_inits_cleanly() {
        let (cx, _handles) = MockContextBuilder::new("my-module")
            .with_config(toml::toml! { sync_interval_seconds = 60 })
            .build();
        let module = MyModule;
        let registration = module.init(cx).await.expect("init should succeed");
        assert!(registration.router.is_some());
    }

    #[tokio::test]
    async fn module_reads_baseline() {
        let mock_behavior = MockBehaviorRead::new()
            .with_baseline(BehaviorBaselineRef {
                device_mac: "aa:bb:cc:dd:ee:ff".into(),
                status: "baselined".into(),
                observation_count: 5000,
                learning_until_unix: 0,
            });

        let (cx, _handles) = MockContextBuilder::new("my-module")
            .with_behavior_read(std::sync::Arc::new(mock_behavior))
            .build();

        let baseline = cx.behavior().unwrap()
            .get_baseline("aa:bb:cc:dd:ee:ff")
            .await
            .expect("baseline should be present");
        assert_eq!(baseline.status, "baselined");
    }
}
```

Available mocks: `MockBehaviorRead`, `MockSwitchRead`, `MockConnectionRead`,
`MockSnapshotRead`, `MockDeviceManagerRead`. Each has a builder API to
preload canned data (`with_baseline`, `with_anomaly`, `with_mac_location`,
etc.).

The `MockHandles` returned alongside the context lets you inject events
into the bus and observe what the module published.

---

## A complete hello-world module

```rust
// crates/hello-world/src/lib.rs
use ion_drift_module_api::*;
use serde::Deserialize;

pub struct HelloWorldModule;

#[derive(Deserialize, Default)]
struct HelloConfig {
    #[serde(default = "default_greeting")]
    greeting: String,
}
fn default_greeting() -> String { "hello".to_string() }

impl Module for HelloWorldModule {
    fn name(&self) -> &'static str { "hello-world" }
    fn version(&self) -> &'static str { env!("CARGO_PKG_VERSION") }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            events: EventSubscriptions {
                subscribe: vec![EventKind::AnomalyDetected],
                publish: vec![],
            },
            ..Capabilities::default()
        }
    }

    async fn init(
        &self,
        cx: ModuleContext,
    ) -> Result<ModuleRegistration, ModuleError> {
        let config: HelloConfig = cx.config_or_default();
        let greeting = config.greeting.clone();

        // HTTP route at /api/modules/hello-world/say
        let router = axum::Router::new().route(
            "/say",
            axum::routing::get(move || {
                let g = greeting.clone();
                async move { g }
            }),
        );

        // Background task that logs every anomaly Drift detects.
        cx.spawn_task("anomaly-logger", |task_cx| async move {
            let mut rx = task_cx.subscribe();
            loop {
                tokio::select! {
                    _ = task_cx.shutdown_signal().cancelled() => break,
                    event = rx.recv() => match event {
                        Ok(DriftEvent::AnomalyDetected(payload)) => {
                            tracing::info!(
                                anomaly_id = payload.anomaly_id,
                                device = %payload.device_mac,
                                severity = %payload.severity,
                                "hello-world module saw anomaly"
                            );
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            }
        });

        Ok(ModuleRegistration {
            router: Some(router),
            ..Default::default()
        })
    }
}
```

That's a complete, working module: ~50 lines, with a route, a background
task, an event subscription, and config loading.

---

## Composing your module into a Drift build

Modules are loaded via a single function in the host crate:

```rust
// crates/ion-drift-web/src/modules.rs (the OSS stub)
use std::sync::Arc;
use ion_drift_module_host::registry::ModuleErased;

pub fn load() -> Vec<Arc<dyn ModuleErased>> {
    Vec::new()
}
```

The OSS stub returns an empty `Vec`. To compose your module into a Drift
build, replace this file (via build-time file overlay, git submodule
overlay, bind mount, or whatever fits your build tooling) with one that
returns your module list:

```rust
use std::sync::Arc;
use ion_drift_module_host::registry::ModuleErased;

pub fn load() -> Vec<Arc<dyn ModuleErased>> {
    vec![
        Arc::new(my_module::MyModule),
        // ... additional modules
    ]
}
```

The OSS Drift repo never sees the replaced file. Operators of the
overlaid build see the Drift binary with your modules loaded; operators
of the stock OSS build see the empty default.

---

## Stability and versioning

`ion-drift-module-api` follows strict semver:

- **Major bumps (1.x → 2.0)** are rare and breaking. Expect them only for
  fundamental API surface changes.
- **Minor bumps (1.0 → 1.1)** are additive only: new event variants, new
  trait methods with default implementations, new capability fields,
  new payload struct versions (`*V2` alongside `*V1`).
- **Patch bumps** are bug fixes, doc updates, and internal improvements.

`ApiVersion::CURRENT` is computed at compile time from the crate's
`CARGO_PKG_VERSION_MAJOR` and `_MINOR`. The host accepts modules whose
major version equals its own and whose minor version is less than or
equal to its own. A module compiled against API 1.1 will NOT load into a
host built with API 1.0.

`ModuleRegistration` and `Capabilities` are `#[non_exhaustive]`. Always
construct them with struct update syntax (`..Default::default()`) so
future field additions don't break your module:

```rust
Ok(ModuleRegistration {
    router: Some(router),
    ..Default::default()
})
```

`DriftEvent` and `EventKind` are also `#[non_exhaustive]`. Always include
a `_ => {}` arm when matching, so future event variants don't break
exhaustiveness checking.

---

## Known limitations in v1.0

- **Connection / Snapshot / DeviceManager state reads are stubs.** The
  traits exist; the host returns `None` from the corresponding accessors.
  Wired implementations come in a future minor bump.
- **Event lag is silently dropped.** If a per-kind broadcast channel
  overflows, the forwarder task swallows the lag and continues. Modules
  do not see `EventError::Lagged`. Treat events as best-effort and
  reconcile from stores periodically.
- **No metrics handle.** `MetricsHandle` was removed from v1.0. Modules
  can use `tracing` for diagnostics. A real metrics surface comes back
  in a future minor bump if/when Drift gains a Prometheus endpoint.
- **No `Module::health` lifecycle method.** Health was removed for the
  same reason — placeholder types should not be frozen into a stable
  contract. May return as a `watch::Receiver<Health>` in a future bump.
- **Modules run in-process.** There is no hard sandbox, no
  capability-based syscall isolation, no out-of-process execution.
  Module crashes are caught (init/shutdown panic guards, task supervisor
  panic catching, HTTP handler panic guard) but a determined module can
  still misbehave through `unsafe`, filesystem access, or network calls.
- **No dynamic loading.** Module list is compile-time only. Adding or
  removing a module requires a Drift rebuild.
- **Single-tenant.** Drift is designed for single-instance deployments.
  Modules see one set of stores, one device manager, one config. Multi-
  tenant deployments run separate Drift instances.

---

## Getting help

- Source: `crates/ion-drift-module-api/` and `crates/ion-drift-module-host/`
- Test harness: `crates/ion-drift-module-api/src/testing.rs`
- The host's actual lifecycle: `crates/ion-drift-module-host/src/registry.rs`
- The event bus implementation: `crates/ion-drift-module-host/src/event_bus.rs`

If something in this guide doesn't match the code, the code is right —
file an issue against this guide.
