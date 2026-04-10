//! Module registry entry point.
//!
//! Returns the list of modules to load at startup. Default is empty.

use std::sync::Arc;

use ion_drift_module_host::registry::ModuleErased;

/// Returns the list of modules loaded at startup.
pub fn load() -> Vec<Arc<dyn ModuleErased>> {
    Vec::new()
}
