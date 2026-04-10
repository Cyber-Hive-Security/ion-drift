//! Return value of [`crate::Module::init`].
//!
//! Static artifacts the module wants the host to install. Currently this
//! is just an Axum router. Dynamic hooks (tasks, event subscriptions) are
//! registered via methods on [`crate::ModuleContext`] during `init`, not
//! returned here.
//!
//! Future minor bumps may add new fields here. Use struct update syntax
//! (`..Default::default()`) when constructing to remain forward-compatible.

use axum::Router;

/// What [`crate::Module::init`] returns.
#[derive(Default)]
#[non_exhaustive]
pub struct ModuleRegistration {
    /// Optional HTTP router mounted at `/api/modules/<name>/`.
    ///
    /// The router is automatically wrapped in the host's module panic guard
    /// and mounted under the module's prefix. Module routes can use any
    /// standard Axum extractors that don't require Drift's app state.
    /// Modules that need to access core state should use the read-only
    /// handles on [`crate::ModuleContext`] instead.
    pub router: Option<Router>,
}
