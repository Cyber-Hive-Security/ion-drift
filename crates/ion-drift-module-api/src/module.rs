//! The core [`Module`] trait and [`ApiVersion`] type.

use crate::capabilities::Capabilities;
use crate::context::ModuleContext;
use crate::error::ModuleError;
use crate::registration::ModuleRegistration;

/// A semantic version pair for the module API contract itself.
///
/// Modules declare which API version they target via
/// [`Module::api_version`]. At startup, the host checks each module against
/// its own [`ApiVersion::CURRENT`] and rejects incompatible modules.
///
/// Compatibility rule: same major, module minor ≤ host minor. Minor bumps are
/// additive only (new events, new capabilities); major bumps are rare and
/// breaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ApiVersion {
    pub major: u16,
    pub minor: u16,
}

/// Const-fn parser for the version env vars (`CARGO_PKG_VERSION_MAJOR`,
/// `CARGO_PKG_VERSION_MINOR`). Cargo emits these as ASCII decimal strings.
const fn parse_u16_from_env(s: &str) -> u16 {
    let bytes = s.as_bytes();
    let mut acc: u16 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        assert!(b >= b'0' && b <= b'9', "non-digit in version env var");
        acc = acc * 10 + (b - b'0') as u16;
        i += 1;
    }
    acc
}

impl ApiVersion {
    /// The API version this crate currently implements.
    ///
    /// Computed at compile time from `CARGO_PKG_VERSION_MAJOR` and
    /// `CARGO_PKG_VERSION_MINOR`, so it tracks the crate version
    /// automatically — no manual updates required when bumping.
    pub const CURRENT: Self = Self {
        major: parse_u16_from_env(env!("CARGO_PKG_VERSION_MAJOR")),
        minor: parse_u16_from_env(env!("CARGO_PKG_VERSION_MINOR")),
    };

    /// Returns true if a module targeting `self` is compatible with a host at `host`.
    pub fn is_compatible_with(&self, host: ApiVersion) -> bool {
        self.major == host.major && self.minor <= host.minor
    }
}

impl std::fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// The contract every module implements.
///
/// A module is a `Send + Sync + 'static` type that declares its capabilities,
/// performs one-time initialization, and optionally provides health and
/// shutdown hooks. The host stores modules as `Arc<dyn ErasedModule>` via an
/// internal adapter; module authors write plain `async fn`.
///
/// # Lifecycle
///
/// 1. The host validates [`Module::name`], [`Module::api_version`], and
///    [`Module::capabilities`] at registration time.
/// 2. The host builds a [`ModuleContext`] containing exactly the capabilities
///    the module declared. Handles to un-declared capabilities are absent.
/// 3. The host calls [`Module::init`]. On `Err`, the module is marked disabled
///    and skipped. Other modules continue.
/// 4. The module's returned [`ModuleRegistration`] is merged into the host's
///    router, health aggregator, and metrics registry.
/// 5. Tasks spawned via `ctx.spawn_task` run under the host's task supervisor
///    with panic recovery.
/// 6. On shutdown, the host calls [`Module::shutdown`] and waits for spawned
///    tasks to complete cooperatively via the shutdown signal.
pub trait Module: Send + Sync + 'static {
    /// Stable module identifier.
    ///
    /// Used as a URL prefix (`/api/modules/<name>/`), a TOML config table key,
    /// and a storage file name. Must match `^[a-z][a-z0-9_-]{1,31}$` — lowercase
    /// letters, digits, hyphens, and underscores, starting with a letter, length
    /// 2–32. The host validates this at registration; modules with invalid
    /// names are marked Disabled and skipped (non-fatal to other modules).
    fn name(&self) -> &'static str;

    /// Semantic version of the module itself (not the API).
    ///
    /// Typically `env!("CARGO_PKG_VERSION")`. Used for diagnostics and the
    /// `GET /api/system/modules` listing.
    fn version(&self) -> &'static str;

    /// Which API version this module was compiled against.
    ///
    /// Defaults to [`ApiVersion::CURRENT`] of the crate the module was built
    /// with. The host rejects modules whose major version differs or whose
    /// minor version exceeds the host's minor.
    fn api_version(&self) -> ApiVersion {
        ApiVersion::CURRENT
    }

    /// Declare the capabilities this module requires.
    ///
    /// The host grants exactly these. The [`ModuleContext`] the module
    /// receives contains only the handles corresponding to declared
    /// capabilities; attempts to use undeclared capabilities fail at the
    /// handle layer.
    fn capabilities(&self) -> Capabilities;

    /// One-time initialization.
    ///
    /// Called exactly once, after the host has built the context. Returns a
    /// [`ModuleRegistration`] describing the module's HTTP router, if any.
    /// Dynamic hooks (tasks, event subscriptions) are registered via methods
    /// on `cx` during this call.
    ///
    /// Errors are non-fatal to Drift: the host logs, marks the module
    /// disabled, and continues with other modules. Panics in `init` are
    /// also caught and have the same effect.
    fn init(
        &self,
        cx: ModuleContext,
    ) -> impl std::future::Future<Output = Result<ModuleRegistration, ModuleError>> + Send;

    /// Optional cooperative shutdown hook.
    ///
    /// Called once on graceful shutdown (SIGTERM). The module should flush
    /// any pending state, signal its tasks to exit via the shutdown signal
    /// from the context, and return when clean. The host applies a global
    /// shutdown timeout; modules that don't return in time are left behind.
    fn shutdown(
        &self,
        _cx: &ModuleContext,
    ) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }
}
