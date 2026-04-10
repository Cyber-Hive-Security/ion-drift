//! Return value of [`crate::Module::init`].
//!
//! Static artifacts the module wants the host to install: an Axum router, an
//! optional health endpoint, and an optional metrics collector. Dynamic
//! hooks (tasks, event subscriptions) are registered via methods on
//! [`crate::ModuleContext`] during `init`, not returned here.

use axum::Router;

/// What [`crate::Module::init`] returns.
#[derive(Default)]
pub struct ModuleRegistration {
    /// Optional HTTP router mounted at `/api/modules/<name>/`.
    ///
    /// The router is automatically wrapped in the host's module panic guard
    /// and mounted under the module's prefix. Routes can use any standard
    /// Axum extractors; the host provides `State<AppState>` if the module
    /// needs access to Drift's app state (typically via a re-export).
    pub router: Option<Router>,

    /// Optional custom health endpoint.
    ///
    /// If `None`, the host uses [`crate::Module::health`] for the default
    /// health response.
    pub health: Option<HealthEndpoint>,

    /// Optional metrics collector for this module. A minimal placeholder in
    /// v1.0; will be expanded when Drift gains a metrics exposition endpoint.
    pub metrics: Option<MetricsCollector>,
}

/// Liveness result for a module.
#[derive(Debug, Clone)]
pub struct Health {
    pub ok: bool,
    pub message: Option<String>,
}

impl Health {
    pub fn ok() -> Self {
        Self { ok: true, message: None }
    }

    pub fn degraded(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: Some(msg.into()),
        }
    }
}

/// Custom health probe the module may install during `init`.
///
/// If set, the host calls this at `GET /api/v1/modules/<name>/health`
/// instead of calling `Module::health`. Use this for probes that need
/// additional state beyond what `ModuleContext` provides.
#[derive(Clone)]
pub struct HealthEndpoint {
    // Opaque placeholder for v1.0. A future minor bump will add a closure
    // type here. For now, always-ok modules can omit this and rely on the
    // default `Module::health` implementation.
    _placeholder: (),
}

impl HealthEndpoint {
    pub fn always_ok() -> Self {
        Self { _placeholder: () }
    }
}

/// Per-module metrics collector.
///
/// v1.0 placeholder. The API will grow to support counter/gauge/histogram
/// registration once the host metrics registry lands.
#[derive(Clone, Default)]
pub struct MetricsCollector {
    _placeholder: (),
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self::default()
    }
}
