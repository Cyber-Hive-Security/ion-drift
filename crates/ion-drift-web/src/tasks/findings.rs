//! Findings lifecycle: the auto-resolve loop for stale findings.
//!
//! Persistence of module findings happens at the ACL boundary in
//! `modules_registry::inbound`, where the URL-path module identity is known
//! and the finding has been clamped; the same clamped finding is then
//! published on the bus for module fan-out.

use std::sync::Arc;
use std::time::Duration;

use ion_drift_storage::FindingsStore;

/// Default cutoff for auto-resolve: 30 days. Critical/high are never
/// auto-resolved (enforced inside `FindingsStore::auto_resolve_stale`).
const AUTO_RESOLVE_CUTOFF_SECS: i64 = 30 * 86400;
/// Cadence for the auto-resolve sweep. Cheap UPDATE — running often is fine.
const AUTO_RESOLVE_INTERVAL_SECS: u64 = 3600;

/// Periodically auto-resolve stale low/medium/info findings.
pub fn spawn_findings_auto_resolver(store: Arc<FindingsStore>) {
    tokio::spawn(async move {
        // Stagger the first sweep so it doesn't race startup.
        tokio::time::sleep(Duration::from_secs(600)).await;
        let mut interval =
            tokio::time::interval(Duration::from_secs(AUTO_RESOLVE_INTERVAL_SECS));
        loop {
            interval.tick().await;
            match store.auto_resolve_stale(AUTO_RESOLVE_CUTOFF_SECS).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(count = n, "findings: auto-resolved stale"),
                Err(e) => tracing::warn!(error = %e, "findings auto-resolve failed"),
            }
        }
    });
}
