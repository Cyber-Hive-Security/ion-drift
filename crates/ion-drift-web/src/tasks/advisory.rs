//! Advisory evaluator — the cadence behind exploitation correlation.
//!
//! Runs independently of the alert engine on purpose: exploitation state must
//! not depend on whether an operator left an alert rule enabled, or on whether
//! that rule happens to be in cooldown. The scan keeps its own log cursor, so
//! the two consumers never drain entries from each other.

use std::time::Duration;

use crate::advisory::exploitation;
use crate::state::AppState;
use crate::task_supervisor::TaskSupervisor;

/// Stagger past startup so the first cycle does not compete with the pollers
/// for the router queue while the snapshot is still warming up.
const STARTUP_DELAY_SECS: u64 = 180;
/// Evaluation cadence. The router log ring buffer holds far more than this
/// covers, so a slower loop than the alert engine loses nothing.
const INTERVAL_SECS: u64 = 900;
/// Observation retention. Matches the evaluator's candidate window, so a
/// finding is always closed out before the evidence behind it is pruned.
const OBSERVATION_RETENTION_SECS: i64 = 30 * 86400;

/// Spawn the supervised advisory evaluation loop.
pub fn spawn_advisory_evaluator(supervisor: &TaskSupervisor, state: AppState) {
    supervisor.spawn("advisory-evaluator", move || {
        let state = state.clone();
        Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(STARTUP_DELAY_SECS)).await;
            tracing::info!(interval_secs = INTERVAL_SECS, "advisory evaluator starting");

            let mut interval = tokio::time::interval(Duration::from_secs(INTERVAL_SECS));
            // Skip missed ticks rather than firing them back-to-back. After a
            // stall the default burst would write several accumulator rows in
            // quick succession, and cross-cycle counting reads that table.
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;

                let scan = exploitation::scan_auth(&state).await;
                for signal in &scan.signals {
                    if let Err(e) = exploitation::note_observation(&state, signal).await {
                        tracing::warn!(error = %e, "advisory: observation write failed");
                    }
                }
                // Accumulator write is per-cycle, not per-signal: one row per
                // surface carrying the cycle's deduped failure count (Phase 3).
                if let Err(e) =
                    exploitation::note_auth_failures(&state, &scan.service_totals).await
                {
                    tracing::warn!(error = %e, "advisory: auth-failure write failed");
                }
                // Cross-cycle judgement over the accumulator (Phase 4): a
                // sustained sub-threshold run becomes a strong signal the
                // evaluator below correlates like any other. Runs after the
                // accumulator write so the window includes this cycle's row.
                if let Err(e) =
                    crate::advisory::sustained::note_sustained(&state, &scan.service_totals)
                        .await
                {
                    tracing::warn!(error = %e, "advisory: sustained evaluation failed");
                }

                if let Err(e) = exploitation::evaluate(&state).await {
                    tracing::warn!(error = %e, "advisory: evaluation failed");
                }

                let cutoff = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64
                    - OBSERVATION_RETENTION_SECS;
                match state.advisory_store.prune_observations(cutoff).await {
                    Ok(0) => {}
                    Ok(n) => tracing::debug!(count = n, "advisory: pruned old observations"),
                    Err(e) => tracing::warn!(error = %e, "advisory: prune failed"),
                }
                match state.advisory_store.prune_auth_failures(cutoff).await {
                    Ok(0) => {}
                    Ok(n) => tracing::debug!(count = n, "advisory: pruned old auth failures"),
                    Err(e) => tracing::warn!(error = %e, "advisory: auth-failure prune failed"),
                }
            }
        })
    });
}
