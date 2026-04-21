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
//! return a [`ModuleRegistration`] from `init`. The host gives the module a
//! [`ModuleContext`] containing handles only for the capabilities it
//! declared — undeclared state reads, secrets, and event subscriptions are
//! absent from the context at runtime.
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
//!         // ModuleRegistration is #[non_exhaustive], so use struct update syntax
//!         // for forward compatibility.
//!         Ok(ModuleRegistration {
//!             router: Some(axum::Router::new()),
//!             ..Default::default()
//!         })
//!     }
//! }
//! ```
//!
//! See `docs/module-developer-guide.md` in the workspace for a longer
//! walkthrough including capabilities, storage, events, testing, and a
//! complete hello-world example.
//!
//! # Capability model
//!
//! Modules are gated by a **runtime capability handle pattern**, not a
//! compile-time type system. The mechanism is:
//!
//! 1. The module returns a [`Capabilities`] struct from `capabilities()`.
//! 2. The host builds a [`ModuleContext`] whose handle fields are populated
//!    only for the capabilities the module asked for. Other fields are
//!    `None` or absent (`cx.behavior()` returns `None` if the module did
//!    not declare `state_reads.behavior = true`).
//! 3. Methods that take a kind argument (like
//!    [`crate::EventHandle::publish`]) check the declared list at runtime
//!    and return an error variant on violations.
//!
//! This is a defense-in-depth boundary, not a hard sandbox. Modules run in
//! the same process as the host; the boundary protects against accidents
//! and misconfiguration, not against modules that genuinely want to break
//! out (e.g. by going through `unsafe` or filesystem APIs).
//!
//! # Stability
//!
//! This crate follows strict semver. Within a major version, changes are
//! additive only. Event payloads are versioned (`*V1`, `*V2`) and the event
//! enum is `#[non_exhaustive]` so new variants are minor bumps. Modules target
//! a specific [`ApiVersion`] and the host rejects incompatible modules at
//! startup.
//!
//! [`ModuleRegistration`] is also `#[non_exhaustive]` — construct it with
//! `..Default::default()` so future field additions don't break your module.

pub mod capabilities;
pub mod context;
pub mod error;
pub mod event;
pub mod module;
pub mod registration;
pub mod state_reads;
pub mod storage;
pub mod wire;

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
pub use wire::{
    DriftEventWire, EventEnvelope, Manifest, ModuleCustomWireV1, ProtocolVariant, RouteDescriptor,
};
