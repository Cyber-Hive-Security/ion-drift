//! Cross-cycle counting (Phase 4) — the reader of `advisory_auth_failure`.
//!
//! Per-cycle detectors are blind to a run paced under their thresholds. This
//! module windows the persisted per-cycle counts the evaluator has been
//! writing (Phase 3) and, when a surface shows a sustained, source-diverse
//! total, emits `auth.login_failure_sustained` as an ordinary attack
//! observation. What that signal confirms — and at what confidence — is
//! catalog data, same as every other signal.

use std::collections::{BTreeMap, BTreeSet};

use ion_drift_storage::advisory::AuthFailure;

use crate::alerting::ServiceFailureTotal;
use crate::state::AppState;

/// Signal id this module emits. Must stay in `signals::EMITTED_SIGNALS`.
pub(crate) const SIGNAL_SUSTAINED: &str = "auth.login_failure_sustained";
/// Sliding window the accumulator is summed over. Must stay well inside the
/// 30-day accumulator retention or hits would be computed from pruned air.
const SUSTAINED_WINDOW_SECS: i64 = 7 * 86400;
/// Deduped failures across the window that make a run worth calling. 2x the
/// per-cycle distributed total.
const SUSTAINED_TOTAL: i64 = 30;
/// Distinct cycles the failures must be spread over. A single loud cycle is
/// the per-cycle detectors' business, not this module's.
const SUSTAINED_MIN_CYCLES: usize = 6;
/// Distinct source IPs across the window. One host retrying a stale
/// credential has volume and persistence but never diversity — this floor is
/// what keeps that benign shape out. Single-source slow runs are a documented
/// blind spot (the accumulator retains no user identities to tell them apart).
const SUSTAINED_MIN_SOURCES: usize = 2;

/// One surface whose window crossed every sustained threshold this cycle.
#[derive(Debug, PartialEq)]
pub(crate) struct SustainedHit {
    pub surface_key: String,
    /// THIS cycle's deduped failure count — never the window total, which
    /// would compound in `evaluate()`'s 24h event_count sum.
    pub event_count: i64,
    /// Distinct sources across the window, sorted.
    pub src_ips: Vec<String>,
    pub window_total: i64,
    pub window_cycles: usize,
}

/// Judge every surface that failed *this* cycle against its window history.
///
/// Pure so the rule is testable without a store. `window_rows` must already be
/// window-bounded (the caller queries `auth_failures_since`) and is expected to
/// include the row the current cycle just wrote — `note_sustained` runs after
/// `note_auth_failures` for exactly that reason.
pub(crate) fn sustained_hits(
    window_rows: &[AuthFailure],
    current: &[ServiceFailureTotal],
    device_id: &str,
) -> Vec<SustainedHit> {
    struct Window {
        total: i64,
        cycles: usize,
        sources: BTreeSet<String>,
    }
    let mut per_surface: BTreeMap<&str, Window> = BTreeMap::new();
    for r in window_rows {
        let w = per_surface.entry(r.surface_key.as_str()).or_insert(Window {
            total: 0,
            cycles: 0,
            sources: BTreeSet::new(),
        });
        w.total += r.failure_count;
        // One row per cycle per surface by construction (sole-writer rule),
        // so the row count IS the distinct-cycle count.
        w.cycles += 1;
        w.sources.extend(r.src_ips.iter().cloned());
    }

    let mut hits = Vec::new();
    for t in current {
        if t.count == 0 {
            continue;
        }
        let surface = super::exploitation::surface_key(device_id, &t.service);
        let Some(w) = per_surface.get(surface.as_str()) else {
            continue;
        };
        if w.total >= SUSTAINED_TOTAL
            && w.cycles >= SUSTAINED_MIN_CYCLES
            && w.sources.len() >= SUSTAINED_MIN_SOURCES
        {
            hits.push(SustainedHit {
                surface_key: surface,
                event_count: t.count as i64,
                src_ips: w.sources.iter().cloned().collect(),
                window_total: w.total,
                window_cycles: w.cycles,
            });
        }
    }
    hits
}

/// Read the window, judge this cycle's surfaces, and persist each hit as an
/// attack observation under [`SIGNAL_SUSTAINED`]. From here the existing
/// exploitation evaluator owns it: catalog linkage, surface scope, the 24h
/// window, re-open and close-out all behave exactly as for per-cycle signals.
pub async fn note_sustained(
    state: &AppState,
    totals: &[ServiceFailureTotal],
) -> Result<(), String> {
    let now = super::exploitation::now_unix();
    let window_rows = state
        .advisory_store
        .auth_failures_since(now - SUSTAINED_WINDOW_SECS)
        .await?;
    let device_id = super::exploitation::primary_device_id(state).await;

    for hit in sustained_hits(&window_rows, totals, &device_id) {
        tracing::warn!(
            surface = %hit.surface_key,
            window_total = hit.window_total,
            window_cycles = hit.window_cycles,
            sources = hit.src_ips.len(),
            "advisory: sustained low-and-slow auth-failure run detected"
        );
        state
            .advisory_store
            .record_observation(
                &device_id,
                &hit.surface_key,
                SIGNAL_SUSTAINED,
                &hit.src_ips,
                hit.event_count,
                now,
            )
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(surface: &str, count: i64, srcs: &[&str], at: i64) -> AuthFailure {
        AuthFailure {
            id: 0,
            device_id: "router-1".into(),
            surface_key: surface.into(),
            failure_count: count,
            src_ips: srcs.iter().map(|s| s.to_string()).collect(),
            observed_at: at,
        }
    }

    fn current(service: &str, count: usize, srcs: &[&str]) -> ServiceFailureTotal {
        ServiceFailureTotal {
            service: service.into(),
            count,
            sources: srcs.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// 10 cycles x 3 failures from alternating sources: invisible per-cycle
    /// (3 < AUTH_BF_WARN_THRESHOLD), unmistakable across the window.
    #[test]
    fn slow_multi_source_run_fires() {
        let rows: Vec<AuthFailure> = (0..10)
            .map(|i| {
                let src = if i % 2 == 0 { "10.0.0.5" } else { "10.0.0.9" };
                row("router-1:svc:api", 3, &[src], 1000 + i * 900)
            })
            .collect();
        let hits = sustained_hits(&rows, &[current("api", 3, &["10.0.0.5"])], "router-1");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].surface_key, "router-1:svc:api");
        assert_eq!(hits[0].event_count, 3, "this cycle's count, never the window total");
        assert_eq!(hits[0].window_total, 30);
        assert_eq!(hits[0].window_cycles, 10);
        assert_eq!(hits[0].src_ips, vec!["10.0.0.5", "10.0.0.9"], "window union, sorted");
    }

    /// One 30-failure burst in a single cycle: loud, but the per-cycle
    /// signals own it. Sustained requires spread.
    #[test]
    fn single_burst_does_not_fire() {
        let rows = vec![row("router-1:svc:api", 30, &["10.0.0.5", "10.0.0.9"], 1000)];
        let hits = sustained_hits(
            &rows,
            &[current("api", 30, &["10.0.0.5", "10.0.0.9"])],
            "router-1",
        );
        assert!(hits.is_empty(), "one cycle < SUSTAINED_MIN_CYCLES");
    }

    /// A stale integration credential: one source, week-long, high volume.
    /// The benign shape the source floor exists to exclude.
    #[test]
    fn single_source_retry_does_not_fire() {
        let rows: Vec<AuthFailure> = (0..10)
            .map(|i| row("router-1:svc:api", 3, &["10.0.0.5"], 1000 + i * 900))
            .collect();
        let hits = sustained_hits(&rows, &[current("api", 3, &["10.0.0.5"])], "router-1");
        assert!(hits.is_empty(), "sources < SUSTAINED_MIN_SOURCES");
    }

    /// Below the window total: spread and diverse, but too quiet to call.
    #[test]
    fn below_total_does_not_fire() {
        let rows: Vec<AuthFailure> = (0..6)
            .map(|i| {
                let src = if i % 2 == 0 { "10.0.0.5" } else { "10.0.0.9" };
                row("router-1:svc:api", 2, &[src], 1000 + i * 900)
            })
            .collect();
        let hits = sustained_hits(&rows, &[current("api", 2, &["10.0.0.5"])], "router-1");
        assert!(hits.is_empty(), "12 < SUSTAINED_TOTAL");
    }

    /// The window may be hot, but a quiet current cycle emits nothing — the
    /// observation stream stays evidence of activity, and a paused run closes
    /// out through the normal 24h ceased path.
    #[test]
    fn quiet_current_cycle_emits_nothing() {
        let rows: Vec<AuthFailure> = (0..10)
            .map(|i| {
                let src = if i % 2 == 0 { "10.0.0.5" } else { "10.0.0.9" };
                row("router-1:svc:api", 3, &[src], 1000 + i * 900)
            })
            .collect();
        let hits = sustained_hits(&rows, &[current("ssh", 4, &["10.0.0.7"])], "router-1");
        assert!(hits.is_empty(), "api is hot but this cycle's failures were on ssh only");
    }

    /// Surfaces are judged independently; ssh noise cannot push api over.
    #[test]
    fn surfaces_do_not_cross_contaminate() {
        let mut rows: Vec<AuthFailure> = (0..10)
            .map(|i| {
                let src = if i % 2 == 0 { "10.0.0.5" } else { "10.0.0.9" };
                row("router-1:svc:ssh", 3, &[src], 1000 + i * 900)
            })
            .collect();
        rows.push(row("router-1:svc:api", 2, &["10.0.0.5"], 9100));
        let hits = sustained_hits(
            &rows,
            &[
                current("api", 2, &["10.0.0.5"]),
                current("ssh", 3, &["10.0.0.5"]),
            ],
            "router-1",
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].surface_key, "router-1:svc:ssh");
    }
}
