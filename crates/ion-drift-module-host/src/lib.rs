//! Runtime host for Ion Drift modules.
//!
//! This crate contains the concrete implementations that power the module
//! API: the registry, the event bus, the storage provisioner, the task
//! adapter, and the HTTP integration glue. Modules depend only on the
//! sibling `ion-drift-module-api` crate; this host crate is consumed by
//! the main web server.

pub mod event_bus;
pub mod panic_guard;
pub mod registry;
pub mod storage_backend;

pub use event_bus::EventBus;
pub use registry::{LoadedModule, ModuleRegistry, ModuleStatus};
