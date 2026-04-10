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
///
/// Every field on `Capabilities` corresponds to something the host actively
/// grants or denies. There are deliberately no purely-advisory bool flags:
/// `routes` and `tasks` are not declared because their use is observable
/// at the right time anyway (a router is returned from `init`, a task is
/// spawned via the supervisor).
#[derive(Debug, Clone, Default)]
pub struct Capabilities {
    /// What kind of storage the module needs.
    pub storage: StorageNeed,

    /// Event bus subscribe/publish declarations.
    pub events: EventSubscriptions,

    /// Which host state stores the module wants read access to.
    pub state_reads: StateReads,

    /// Named secrets the module needs.
    ///
    /// Names MUST be prefixed with `MODULE_<UPPER_NAME>_` where `UPPER_NAME`
    /// is the module's [`crate::Module::name`] with hyphens converted to
    /// underscores and uppercased. Modules with secret names that don't
    /// match this prefix are rejected at registration with `Disabled`
    /// status. This prevents modules from declaring secret names belonging
    /// to Drift core (e.g. `DRIFT_SESSION_SECRET`) and reading them via
    /// `ctx.secret(...)`.
    ///
    /// Example: a module named `"hello-world"` can declare
    /// `secrets: vec!["MODULE_HELLO_WORLD_API_KEY"]`.
    pub secrets: Vec<&'static str>,
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
