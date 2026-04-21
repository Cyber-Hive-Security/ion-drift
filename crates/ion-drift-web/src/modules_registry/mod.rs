//! Registry of out-of-process Drift modules.
//!
//! This module owns the persistence layer for Module API v1.1 modules
//! registered by a Drift admin via the UI. Each registered module is an
//! independent HTTP service that Drift
//!
//! - delivers subscribed events to via signed POSTs (see the event
//!   dispatcher, Task 4), and
//! - reverse-proxies admin-authenticated Drift UI requests to (see the
//!   module proxy route, Task 5).
//!
//! Per-registration secrets (HMAC signing key for outbound events, bearer
//! token for outbound proxy calls) are encrypted with the same KEK that
//! protects `oidc_client_secret` and `router_password` and live in the
//! same `secrets.db` file.

pub mod dispatcher;
pub mod service;
pub mod store;

pub use dispatcher::{
    sign_bytes, DeliveryStats, DispatcherConfig, EventDispatcher, SIGNATURE_HEADER,
};
pub use service::{validate_manifest, ModuleRegistryService, RegisterRequest};
pub use store::{ModuleRegistryStore, NewModuleRegistration, RegisteredModule};
