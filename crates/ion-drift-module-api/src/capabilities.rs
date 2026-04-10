//! Capability declarations — what a module asks the host to grant.
//!
//! Each module returns a [`Capabilities`] struct from [`crate::Module::capabilities`].
//! The host grants exactly these and builds a [`crate::ModuleContext`] whose
//! handles correspond to the declared set. Handles to undeclared capabilities
//! are `None` or otherwise absent — modules cannot reach anything they didn't
//! ask for.

use crate::event::EventKind;

/// What a module declares it needs from the host.
///
/// Default is "nothing" — the empty module. Set specific fields to opt in.
#[derive(Debug, Clone, Default)]
pub struct Capabilities {
    /// True if the module returns an Axum router from `init`.
    /// The router will be mounted at `/api/modules/<name>/`.
    pub routes: bool,

    /// True if the module will spawn background tasks via `ctx.spawn_task`.
    pub tasks: bool,

    /// What kind of storage the module needs.
    pub storage: StorageNeed,

    /// Event bus subscribe/publish declarations.
    pub events: EventSubscriptions,

    /// Which host state stores the module wants read access to.
    pub state_reads: StateReads,

    /// Named secrets the module needs (env var or keyring keys).
    ///
    /// Only listed secrets will be resolvable via `ctx.secrets`. Empty by
    /// default. Names are arbitrary but should be screaming snake case
    /// (e.g. `"MY_MODULE_API_KEY"`).
    pub secrets: Vec<&'static str>,

    /// True if the module registers metrics via `ctx.metrics`.
    pub metrics: bool,

    /// True if the module provides a [`crate::HealthEndpoint`] in registration.
    pub health: bool,
}

/// How much persistent storage the module wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StorageNeed {
    /// Module has no persistent state.
    #[default]
    None,
    /// Module gets its own SQLite file at `${data_dir}/modules/<name>.db`.
    /// Schema and migrations are entirely module-owned.
    Isolated,
}

/// Declared event subscriptions and publications.
///
/// The host enforces these at the channel layer. A module that declares
/// `publish: [AnomalyDetected]` cannot publish any other event — attempts
/// return [`crate::EventError::NotDeclared`]. A module that declares
/// `subscribe: [AnomalyDetected]` will only receive that event; its receiver
/// automatically filters the bus.
#[derive(Debug, Clone, Default)]
pub struct EventSubscriptions {
    pub subscribe: Vec<EventKind>,
    pub publish: Vec<EventKind>,
}

/// Which host state stores the module wants read access to.
///
/// All flags default to `false`. If a flag is `false`, the corresponding
/// accessor on [`crate::ModuleContext`] returns `None`, enforcing the
/// capability boundary at the type level.
#[derive(Debug, Clone, Copy, Default)]
pub struct StateReads {
    pub behavior: bool,
    pub switch: bool,
    pub connection: bool,
    pub snapshot: bool,
    pub devices: bool,
}
