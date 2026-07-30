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
            loop {
                interval.tick().await;

                for signal in exploitation::scan_auth_signals(&state).await {
                    if let Err(e) = exploitation::note_observation(&state, &signal).await {
                        tracing::warn!(error = %e, "advisory: observation write failed");
                    }
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
            }
        })
    });
}
