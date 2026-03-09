mod sanitizer;

pub use sanitizer::DemoSanitizer;

use std::sync::OnceLock;

static DEMO_MODE: OnceLock<bool> = OnceLock::new();

/// Check if the application is running in demo mode (`ION_DRIFT_MODE=demo`).
pub fn is_demo_mode() -> bool {
    *DEMO_MODE.get_or_init(|| {
        std::env::var("ION_DRIFT_MODE")
            .map(|v| v.eq_ignore_ascii_case("demo"))
            .unwrap_or(false)
    })
}
