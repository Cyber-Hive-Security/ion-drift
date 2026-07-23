//! Findings consumer — bridges the in-process EventBus to the persistent
//! `FindingsStore`, and runs the auto-resolve loop for stale findings.
//!
//! The inbound publish endpoint (`modules_registry::inbound`) host-stamps
//! the emitting module's name and publishes a `DriftEvent::Finding` onto
//! the bus. This task is the durable consumer: it upserts every finding
//! into `findings.db`. The dispatcher will *also* see the same event and
//! fan it out to any subscribed module — that's an emergent capability,
//! not coupled to persistence.

use std::sync::Arc;
use std::time::Duration;

use ion_drift_module_api::{DriftEvent, EventKind};
use ion_drift_module_host::EventBus;
use ion_drift_storage::FindingsStore;

/// Default cutoff for auto-resolve: 30 days. Critical/high are never
/// auto-resolved (enforced inside `FindingsStore::auto_resolve_stale`).
const AUTO_RESOLVE_CUTOFF_SECS: i64 = 30 * 86400;
/// Cadence for the auto-resolve sweep. Cheap UPDATE — running often is fine.
const AUTO_RESOLVE_INTERVAL_SECS: u64 = 3600;

/// Subscribe to `EventKind::Finding` for emergent fan-out. Inbound
/// findings are persisted at the ACL boundary in `inbound.rs` where the
/// URL-path module identity is known; the bus payload (`FindingV1`)
/// deliberately omits `module_name`. This task exists so any future
/// in-process emitter that publishes a `Finding` directly onto the bus
/// still lands a durable row, stamped `"in-process"`.
pub fn spawn_findings_consumer(store: Arc<FindingsStore>, event_bus: EventBus) {
    tokio::spawn(async move {
        let handle = event_bus.handle_for(
            "findings-consumer",
            Vec::new(),
            vec![EventKind::Finding],
        );
        let mut rx = handle.subscribe();
        tracing::info!("findings consumer started");
        loop {
            match rx.recv().await {
                Ok(DriftEvent::Finding(finding)) => {
                    if let Err(e) = store
                        .upsert_finding("in-process", &finding, None, None)
                        .await
                    {
                        tracing::warn!(error = %e, "findings consumer: upsert failed");
                    }
                }
                Ok(_) => {}
                Err(ion_drift_module_api::EventError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "findings consumer lagged");
                }
                Err(_) => break,
            }
        }
        tracing::info!("findings consumer stopped");
    });
}

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
