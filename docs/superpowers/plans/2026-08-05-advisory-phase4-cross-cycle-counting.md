# Advisory Phase 4 — Cross-Cycle Counting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Read the `advisory_auth_failure` accumulator across evaluator cycles and emit a new strong signal — `auth.login_failure_sustained` — when a surface shows a sustained low-and-slow credential-guessing run that no single cycle's thresholds could see.

**Architecture:** Phase 4 adds **no new finding machinery**. It computes a sustained-attack judgement from the Phase 3 accumulator and records it as an ordinary attack observation (`record_observation`) under a new signal id. The existing `evaluate()` then correlates, opens, re-opens and closes findings exactly as it does for the other three signals — which advisories the signal confirms, and at what confidence, stays a catalog edit ("core never names a CVE in a Rust literal"). The detection rule's shape excludes the classic false positive (a stale integration credential retrying for a week) by requiring source diversity, and excludes single bursts (already covered per-cycle) by requiring cycle spread.

**Tech Stack:** Rust workspace at `/home/yodaadmin/ion-drift`, branch `development`. Everything builds on Phase 3 (shipped through `4bd2d05`): `AdvisoryStore::auth_failures_since`, `ServiceFailureTotal`, the evaluator loop in `tasks/advisory.rs`.

## Global Constraints

- Branch `development`; Conventional Commits; TDD with RED proven first.
- Windowed counting + prune, NO EWMA (ADR PATTERNS). The sustained rule is a windowed sum over persisted rows — no decaying scores.
- No schema change: Phase 4 is read-only against `advisory_auth_failure` and write-only through the existing `record_observation` path. Do NOT bump `SCHEMA_VERSION`.
- Core emits behaviour, catalog assigns meaning: the new signal id goes in `signals.rs` + the seed catalog; confidence lives ONLY in catalog JSON.
- `cargo test --workspace` green and `cargo-deny ≥0.20 check` ok before claiming done (no new deps expected).
- Host caveat (Viscid): openssl scratchpad-prefix workaround per memory `ion-drift-build-env-viscid.md`; use prebuilt cargo-deny ≥0.20 (0.18.x chokes on CVSS 4.0 in the RustSec DB).
- ion-drift-web has parallel module trees in `lib.rs` AND `main.rs` — new modules under `advisory/` need no root registration (the `advisory` module is already in both), but keep this in mind for any new top-level file.

## The Detection Rule (the heart — agreed defaults, all tunable constants)

Over a sliding window of the accumulator, per surface:

| Constant | Value | Why |
|---|---|---|
| `SUSTAINED_WINDOW_SECS` | `7 * 86400` | Long enough that 2–4 failures/cycle (invisible per-cycle) accumulates a clear total; well inside the 30-day accumulator retention. |
| `SUSTAINED_TOTAL` | `30` | 2× the per-cycle distributed total (15); unreachable by noise, reachable in under a day by a real slow run (e.g. 2/cycle × 15 cycles). |
| `SUSTAINED_MIN_CYCLES` | `6` | Excludes single bursts — one loud cycle already fires the per-cycle signals; "sustained" must mean *spread across cycles* (≥1.5 h of persistence at the 900 s cadence). |
| `SUSTAINED_MIN_SOURCES` | `2` | Excludes the stale-integration retry (one host, one dead password, metronomic) — the highest-volume benign shape that would otherwise satisfy total+cycles. Single-source slow runs are a documented blind spot; with no user diversity retained in the accumulator, one source + one service is indistinguishable from a broken cron job. |

A hit fires only on a cycle where the surface **also had failures right now** (`ServiceFailureTotal.count > 0`), and the emitted observation's `event_count` is **this cycle's count**, not the window total — `evaluate()` sums `event_count` across observations in its 24 h window, so emitting the window total every 900 s would compound into nonsense evidence. Window totals ride in the tracing log line instead. Quiet cycles emit nothing; if the run pauses >24 h the finding closes as "exploitation signal ceased" and re-opens on resumption — the exact semantics the other signals already have.

## File Structure

| File | Responsibility |
|---|---|
| `crates/ion-drift-web/src/advisory/sustained.rs` (create) | Constants, `SustainedHit`, pure `sustained_hits()`, async `note_sustained()` writer |
| `crates/ion-drift-web/src/advisory/mod.rs` (modify) | `pub mod sustained;` |
| `crates/ion-drift-web/src/advisory/signals.rs` (modify) | `auth.login_failure_sustained` in `EMITTED_SIGNALS` |
| `data/advisories/mikrotik.json` (modify) | New signal link on CVE-2026-16347 (confidence `strong`), `catalog_version` 1→2 |
| `crates/ion-drift-web/src/tasks/advisory.rs` (modify) | Call `note_sustained` after `note_auth_failures`, before `evaluate` |

---

### Task 1: Register the signal — registry and seed catalog together

**Files:**
- Modify: `crates/ion-drift-web/src/advisory/signals.rs`
- Modify: `data/advisories/mikrotik.json`

**Interfaces:**
- Produces (Tasks 2–3 rely on): the signal id string `"auth.login_failure_sustained"`, valid per `is_known_signal` and linked in the bundled catalog.

The existing bidirectional tests are the harness here: `emitted_signals_are_all_linked_in_the_catalog` (exploitation.rs:859) fails the moment the registry grows without the catalog, and `catalog_signal_ids_are_all_emitted` (:837) fails the reverse. Use that as the RED step.

- [ ] **Step 1 (RED): add to the registry only**

In `signals.rs`:

```rust
pub const EMITTED_SIGNALS: &[&str] = &[
    "auth.login_failure_burst",
    "auth.login_failure_same_second_burst",
    "auth.login_failure_distributed",
    "auth.login_failure_sustained",
];
```

Run: `cargo test -p ion-drift-web emitted_signals_are_all_linked`
Expected: **FAIL** — the seed catalog does not link the new signal. (This is the plan's RED evidence; capture the output.)

- [ ] **Step 2 (GREEN): add the catalog link + bump the version**

In `data/advisories/mikrotik.json`: set `"catalog_version": 2`, update `"generated_at"` to `"2026-08-05"`, and append to the CVE-2026-16347 `"signals"` array (after the `auth.login_failure_distributed` object):

```json
        {
          "signal_id": "auth.login_failure_sustained",
          "confidence": "strong",
          "description": "Failed logins against this service kept arriving across many polling cycles — thirty or more inside a week, spread over at least six separate cycles and at least two distinct sources — while no single cycle was loud enough to trip a per-cycle detector. That is the shape of a run deliberately paced to stay under burst thresholds, and pacing is only worth an attacker's effort where nothing locks the account and nothing rate-limits the service — the property this advisory describes. The two-source floor is what separates this from the loudest benign look-alike, an integration retrying a stale credential from one host: a single machine with a dead password produces volume and persistence, but not source diversity."
        }
```

Run: `cargo test -p ion-drift-web emitted_signals_are_all_linked && cargo test -p ion-drift-web catalog_signal_ids_are_all_emitted && cargo test -p ion-drift-web advisory`
Expected: PASS (both directions + the rest of the advisory suite, including catalog loader tests against the seed).

- [ ] **Step 3: Commit**

```bash
git add crates/ion-drift-web/src/advisory/signals.rs data/advisories/mikrotik.json
git commit -m "feat(advisory): register auth.login_failure_sustained signal (catalog v2)"
```

---

### Task 2: The pure sustained rule

**Files:**
- Create: `crates/ion-drift-web/src/advisory/sustained.rs`
- Modify: `crates/ion-drift-web/src/advisory/mod.rs` (add `pub mod sustained;` after `pub mod signals;`)

**Interfaces:**
- Consumes: `ion_drift_storage::advisory::AuthFailure { device_id, surface_key, failure_count, src_ips, observed_at, .. }`; `crate::alerting::ServiceFailureTotal { service, count, sources }`; `super::exploitation`'s `surface_key(device_id, service)` — make that helper `pub(crate)` in exploitation.rs (it is currently private; one-word change).
- Produces (Task 3 relies on):
  - `pub(crate) const SIGNAL_SUSTAINED: &str = "auth.login_failure_sustained";`
  - `pub(crate) struct SustainedHit { pub surface_key: String, pub event_count: i64, pub src_ips: Vec<String>, pub window_total: i64, pub window_cycles: usize }`
  - `pub(crate) fn sustained_hits(window_rows: &[AuthFailure], current: &[ServiceFailureTotal], device_id: &str) -> Vec<SustainedHit>`

- [ ] **Step 1: Write the failing tests** (in the new file's `#[cfg(test)]` module)

```rust
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

    /// 10 cycles × 3 failures from alternating sources: invisible per-cycle
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
        let hits = sustained_hits(&rows, &[current("api", 30, &["10.0.0.5", "10.0.0.9"])], "router-1");
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
            &[current("api", 2, &["10.0.0.5"]), current("ssh", 3, &["10.0.0.5"])],
            "router-1",
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].surface_key, "router-1:svc:ssh");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ion-drift-web sustained`
Expected: FAIL to compile — module/`sustained_hits` not found.

- [ ] **Step 3: Implement**

```rust
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
/// Deduped failures across the window that make a run worth calling. 2× the
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
```

Also in `exploitation.rs`, change `fn surface_key(` to `pub(crate) fn surface_key(` and in `advisory/mod.rs` add `pub mod sustained;`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ion-drift-web sustained`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ion-drift-web/src/advisory/sustained.rs crates/ion-drift-web/src/advisory/mod.rs crates/ion-drift-web/src/advisory/exploitation.rs
git commit -m "feat(advisory): pure sustained-run rule over the auth-failure window"
```

---

### Task 3: Wire the writer into the evaluator loop

**Files:**
- Modify: `crates/ion-drift-web/src/advisory/sustained.rs` (add `note_sustained`)
- Modify: `crates/ion-drift-web/src/tasks/advisory.rs`

**Interfaces:**
- Consumes: `AdvisoryStore::{auth_failures_since, record_observation}`, `exploitation::primary_device_id` (make `pub(crate)` — currently private, same one-word change as `surface_key`), `scan.service_totals` already available in the loop.
- Produces: `pub async fn note_sustained(state: &AppState, totals: &[ServiceFailureTotal]) -> Result<(), String>`

- [ ] **Step 1: Implement `note_sustained`** (append to sustained.rs)

```rust
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
```

(`now_unix` in exploitation.rs is private too — make it `pub(crate)` alongside `primary_device_id`.)

- [ ] **Step 2: Call it from the loop** — in `tasks/advisory.rs`, directly after the `note_auth_failures` block (order matters: the window read must include this cycle's accumulator row) and before `evaluate`:

```rust
                // Cross-cycle judgement over the accumulator (Phase 4): a
                // sustained sub-threshold run becomes a strong signal the
                // evaluator below correlates like any other.
                if let Err(e) =
                    crate::advisory::sustained::note_sustained(&state, &scan.service_totals).await
                {
                    tracing::warn!(error = %e, "advisory: sustained evaluation failed");
                }
```

- [ ] **Step 3: Full advisory suite**

Run: `cargo test -p ion-drift-web advisory && cargo test -p ion-drift-web alerting`
Expected: all pass — including the two registry↔catalog tests, which now also cover the new signal end-to-end (it is emitted by `note_sustained` and linked in the seed).

- [ ] **Step 4: Commit**

```bash
git add crates/ion-drift-web/src/advisory/sustained.rs crates/ion-drift-web/src/advisory/exploitation.rs crates/ion-drift-web/src/tasks/advisory.rs
git commit -m "feat(advisory): evaluator emits sustained signal from cross-cycle window (phase 4)"
```

---

### Task 4: Full verification + phase-marker docs + push

- [ ] **Step 1:** `cargo test --workspace` — 0 failures (baseline from Phase 3/skeleton work + 6 new sustained tests).
- [ ] **Step 2:** `cargo-deny ≥0.20 check` — advisories/bans/licenses/sources ok (no new deps).
- [ ] **Step 3:** Update `crates/ion-drift-storage/src/advisory.rs:105-107` comment: `"the persisted state cross-cycle counting (Phase 4) reads"` → `"the persisted state cross-cycle counting (Phase 4, wired — see advisory/sustained.rs) reads"`.
- [ ] **Step 4: Commit + push**

```bash
git add crates/ion-drift-storage/src/advisory.rs
git commit -m "docs(advisory): mark phase-4 reader as wired in schema comment"
git push origin development
```

---

## Out of Scope (deliberately)

- The `advisory_suppression` table wiring (durable operator suppression) — separate, pre-existing gap, noted in `evaluate()`'s doc comment.
- Any per-user tracking in the accumulator (would sharpen the single-source blind spot but needs a schema change).
- Catalog feed refresh (6 h advisories / 24 h watchlist — the agreed cadences for the future generic updater).

## Self-Review Notes

- Spec coverage: "persisted state cross-cycle counting (Phase 4) reads" — Task 3's `auth_failures_since` read is the promised reader; sole-writer rule preserved (Phase 4 writes only through `record_observation`, never touches `advisory_auth_failure`).
- The one design call to surface: `event_count` = current-cycle count (not window total) to keep `evaluate()`'s summation meaningful — rationale in the Detection Rule table and the `SustainedHit` doc comment. Window totals are logged, not persisted.
- Type consistency: `SustainedHit` fields identical in Tasks 2–3; `sustained_hits(window_rows, current, device_id)` arity matches; `surface_key`/`primary_device_id`/`now_unix` visibility changes named in both tasks that need them.
