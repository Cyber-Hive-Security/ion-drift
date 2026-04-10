//! Error types for the module API.

/// Errors returned from module lifecycle methods and context operations.
#[derive(thiserror::Error, Debug)]
pub enum ModuleError {
    /// Module config failed to load or deserialize.
    #[error("module config invalid: {0}")]
    Config(String),

    /// Module attempted to use a capability it did not declare.
    #[error("capability not granted: {0}")]
    CapabilityMissing(&'static str),

    /// Underlying storage operation failed.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    /// Event bus operation failed.
    #[error("event error: {0}")]
    Event(#[from] EventError),

    /// Module init failed with an arbitrary reason.
    #[error("init failed: {0}")]
    Init(String),

    /// Any other error, preserved as the source.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Errors from per-module storage operations.
#[derive(thiserror::Error, Debug)]
pub enum StorageError {
    /// SQLite error wrapping [`rusqlite::Error`].
    ///
    /// The error message is preserved as a string so this type does not force
    /// consumers to depend on rusqlite directly.
    #[error("sqlite: {0}")]
    Sqlite(String),

    /// IO error (file open, directory create, etc.).
    #[error("io: {0}")]
    Io(String),

    /// Migration failed.
    #[error("migration failed: {name}: {reason}")]
    Migration { name: String, reason: String },

    /// Storage was requested but the capability was not declared.
    #[error("storage not granted to this module")]
    NotGranted,
}

/// Errors from event bus operations.
#[derive(thiserror::Error, Debug)]
pub enum EventError {
    /// Module tried to publish an event kind it did not declare in
    /// [`crate::EventSubscriptions::publish`].
    #[error("event kind not declared for publish: {0:?}")]
    NotDeclared(crate::event::EventKind),

    /// Module tried to publish a `DriftEvent::ModuleCustom` via the plain
    /// `publish` method. Use `publish_custom(kind, payload)` instead so the
    /// source field is host-stamped and cannot be spoofed.
    #[error("DriftEvent::ModuleCustom must be published via publish_custom")]
    CustomMustUsePublishCustom,

    /// The event bus was closed (host is shutting down).
    #[error("event bus closed")]
    Closed,

    /// Subscriber lagged behind. The next recv will resync from the tail.
    #[error("subscriber lagged by {0} events")]
    Lagged(u64),
}

// anyhow is a convenience re-export so modules don't have to add it
// themselves for `ModuleError::Other`. The feature bar is standard.
pub use anyhow;
