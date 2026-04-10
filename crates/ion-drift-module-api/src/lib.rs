//! Ion Drift Module API — the stable contract between Ion Drift and modules
//! that extend it.
//!
//! # Overview
//!
//! A module is a self-contained extension that plugs into Ion Drift without
//! modifying core. Modules can register HTTP routes, spawn background tasks,
//! read (but not write) core state, subscribe to events, and own isolated
//! storage. They are composed into the final binary by an explicit list in
//! the host application.
//!
//! This crate contains only trait and type definitions. The runtime wiring
//! lives in a separate host crate. Modules depend only on this crate, so the
//! host's internals can evolve without forcing modules to recompile.
//!
//! # Writing a module
//!
//! Implement the [`Module`] trait, declare required [`Capabilities`], and
//! return a [`ModuleRegistration`] from `init`. The host grants only the
//! capabilities declared — anything else is unavailable at compile time.
//!
//! ```rust,ignore
//! use ion_drift_module_api::*;
//!
//! pub struct MyModule;
//!
//! impl Module for MyModule {
//!     fn name(&self) -> &'static str { "my-module" }
//!     fn version(&self) -> &'static str { env!("CARGO_PKG_VERSION") }
//!
//!     fn capabilities(&self) -> Capabilities {
//!         Capabilities::default()
//!     }
//!
//!     async fn init(&self, _cx: ModuleContext) -> Result<ModuleRegistration, ModuleError> {
//!         Ok(ModuleRegistration {
//!             router: Some(axum::Router::new()),
//!         })
//!     }
//! }
//! ```
//!
//! # Stability
//!
//! This crate follows strict semver. Within a major version, changes are
//! additive only. Event payloads are versioned (`*V1`, `*V2`) and the event
//! enum is `#[non_exhaustive]` so new variants are minor bumps. Modules target
//! a specific [`ApiVersion`] and the host rejects incompatible modules at
//! startup.

pub mod capabilities;
pub mod context;
pub mod error;
pub mod event;
pub mod module;
pub mod registration;
pub mod state_reads;
pub mod storage;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

// Re-exports: the flat public surface module authors use.
pub use capabilities::{Capabilities, EventSubscriptions, StateReads, StorageNeed};
pub use context::{
    EventHandle, EventReceiver, ModuleConfigHandle, ModuleContext, SecretsHandle,
    ShutdownSignal, StateReadHandles, TaskSupervisorHandle,
};
pub use error::{EventError, ModuleError, StorageError};
pub use event::{
    AnomalyDetectedV1, BehaviorBaselineUpdatedV1, ConnectionStateChangedV1, DeviceAddedV1,
    DeviceRemovedV1, DeviceUnreachableV1, DriftEvent, EventKind,
    InfrastructureSnapshotUpdatedV1, InvestigationCompletedV1, InvestigationStartedV1,
    SwitchTopologyChangedV1,
};
pub use module::{ApiVersion, Module};
pub use registration::ModuleRegistration;
pub use state_reads::{
    BehaviorRead, ConnectionRead, DeviceManagerRead, SnapshotRead, SwitchRead,
};
pub use storage::{Migration, ModuleStorage};
