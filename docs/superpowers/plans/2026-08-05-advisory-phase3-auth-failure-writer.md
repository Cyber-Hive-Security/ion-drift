# Advisory Phase 3 — Auth-Failure Accumulator Writer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the advisory evaluator to write the `advisory_auth_failure` accumulator — one row per evaluator cycle per surface carrying that cycle's deduped login-failure count — so Phase 4's cross-cycle counting has persisted state to read.

**Architecture:** Phase 2 (commit `d6b569c`) created the `advisory_auth_failure` table schema-only: no accessors, no writer. Phase 3 adds (1) storage accessors on `AdvisoryStore` mirroring the existing observation methods, (2) per-service deduped failure totals computed in the auth scan *before* thresholding — `BruteforceSignal` only exists above alert thresholds, but the whole point of cross-cycle counting is catching low-and-slow runs that never cross a per-cycle threshold, so the writer must see sub-threshold failures too — and (3) the evaluator loop writing one row per surface per cycle plus pruning. The advisory evaluator is the table's **sole writer** (ADR sole-writer rule for detection state).

**Tech Stack:** Rust workspace at `/home/yodaadmin/ion-drift`, branch `development`. rusqlite behind `AdvisoryStore` (advisory.db), tokio tasks, existing alerting parser in `crates/ion-drift-web/src/alerting.rs`.

## Global Constraints

- Work on branch `development`; everything is UNRELEASED (main lags at v0.5.2b).
- Conventional Commits, imperative mood, subject ≤72 chars.
- TDD: every test proven RED before the implementation lands (this repo's checkpoint discipline requires the failing output shown).
- Decay convention is **windowed counting + prune. NO EWMA anywhere** (ADR PATTERNS — a change contradicting it must update the ADR in the same commit).
- No schema change is needed or allowed here: `advisory_auth_failure` exists at schema v2. Do NOT bump `SCHEMA_VERSION`, do NOT touch `MIGRATION_STEPS`.
- `advisory_auth_failure` has exactly one writer: the advisory evaluator. Nothing in alerting may write it.
- Verify with `cargo test --workspace` (baseline: 435 passing as of cp100) and `cargo deny check` before claiming done.
- Host caveat (this dev box, Viscid): `openssl-sys` needs the scratchpad libssl prefix workaround (`OPENSSL_STATIC=1` + extracted libssl-dev .deb + copied `opensslconf.h`) — see memory `ion-drift-build-env-viscid.md`. Budget for it or build where libssl-dev exists.

## File Structure

| File | Responsibility |
|---|---|
| `crates/ion-drift-storage/src/advisory.rs` (modify) | `AuthFailure` row type + `record_auth_failure` / `auth_failures_since` / `prune_auth_failures` accessors |
| `crates/ion-drift-web/src/alerting.rs` (modify) | `ServiceFailureTotal`, `AuthScan`, `service_failure_totals()`; scan returns `AuthScan` |
| `crates/ion-drift-web/src/advisory/exploitation.rs` (modify) | `auth_failure_rows()` (pure) + `note_auth_failures()` (persists); `scan_auth` wrapper returns `AuthScan` |
| `crates/ion-drift-web/src/tasks/advisory.rs` (modify) | Evaluator loop: one scan feeds both observations and the accumulator; prune both tables |

---

### Task 1: Storage accessors for `advisory_auth_failure`

**Files:**
- Modify: `crates/ion-drift-storage/src/advisory.rs`

**Interfaces:**
- Consumes: existing `advisory_auth_failure` table (v2 DDL at `advisory.rs:97-107`), `Self::map_observation` as the pattern to mirror.
- Produces (Tasks 3–4 rely on these exact signatures):
  - `pub struct AuthFailure { pub id: i64, pub device_id: String, pub surface_key: String, pub failure_count: i64, pub src_ips: Vec<String>, pub observed_at: i64 }`
  - `pub async fn record_auth_failure(&self, device_id: &str, surface_key: &str, failure_count: i64, src_ips: &[String], observed_at: i64) -> Result<(), String>`
  - `pub async fn auth_failures_since(&self, cutoff: i64) -> Result<Vec<AuthFailure>, String>`
  - `pub async fn prune_auth_failures(&self, cutoff: i64) -> Result<usize, String>`

- [ ] **Step 1: Write the failing tests** (in the existing `#[cfg(test)]` module of `advisory.rs`, next to `prune_observations_deletes_only_older_than_cutoff`)

```rust
#[tokio::test]
async fn auth_failure_roundtrip_newest_first() {
    let f = NamedTempFile::new().unwrap();
    let store = AdvisoryStore::new(f.path()).await.unwrap();

    let ips = vec!["10.0.0.9".to_string(), "10.0.0.7".to_string()];
    store
        .record_auth_failure("router-1", "router-1:svc:ssh", 4, &ips, 100)
        .await
        .unwrap();
    store
        .record_auth_failure("router-1", "router-1:svc:api", 1, &[], 200)
        .await
        .unwrap();

    let rows = store.auth_failures_since(0).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].observed_at, 200, "newest first");
    assert_eq!(rows[0].surface_key, "router-1:svc:api");
    assert_eq!(rows[0].failure_count, 1);
    assert!(rows[0].src_ips.is_empty(), "console-only cycle has no sources");
    assert_eq!(rows[1].src_ips, ips, "src_ips survive the JSON roundtrip");

    let recent = store.auth_failures_since(150).await.unwrap();
    assert_eq!(recent.len(), 1, "cutoff is inclusive-forward like observations_since");
}

#[tokio::test]
async fn prune_auth_failures_deletes_only_older_than_cutoff() {
    let f = NamedTempFile::new().unwrap();
    let store = AdvisoryStore::new(f.path()).await.unwrap();
    for ts in [100, 200, 300] {
        store
            .record_auth_failure("router-1", "router-1:svc:ssh", 2, &[], ts)
            .await
            .unwrap();
    }
    let deleted = store.prune_auth_failures(200).await.unwrap();
    assert_eq!(deleted, 1, "only the ts=100 row is older than the cutoff");
    let left = store.auth_failures_since(0).await.unwrap();
    assert_eq!(left.len(), 2);
    assert_eq!(left[1].observed_at, 200, "cutoff row is retained");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ion-drift-storage auth_failure -- --nocapture`
Expected: FAIL to compile — `record_auth_failure` / `auth_failures_since` / `prune_auth_failures` / `AuthFailure` not found. (Compile failure is the RED state for missing API.)

- [ ] **Step 3: Implement** — add below `AttackObservation` and mirror the observation accessors exactly:

```rust
/// One accumulator row: the deduped login-failure count one evaluator cycle
/// observed on one surface. Raw per-cycle state, not a conclusion — Phase 4's
/// cross-cycle counting windows these rows and decides what to surface.
/// Sole writer: the advisory evaluator (see tasks/advisory.rs).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthFailure {
    pub id: i64,
    pub device_id: String,
    pub surface_key: String,
    pub failure_count: i64,
    pub src_ips: Vec<String>,
    pub observed_at: i64,
}
```

and in `impl AdvisoryStore` (place after `prune_observations`):

```rust
    pub async fn record_auth_failure(
        &self,
        device_id: &str,
        surface_key: &str,
        failure_count: i64,
        src_ips: &[String],
        observed_at: i64,
    ) -> Result<(), String> {
        let src_ips_json =
            serde_json::to_string(src_ips).map_err(|e| format!("serialize src_ips: {e}"))?;
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO advisory_auth_failure
                (device_id, surface_key, failure_count, src_ips, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![device_id, surface_key, failure_count, src_ips_json, observed_at],
        )
        .map_err(|e| format!("record_auth_failure failed: {e}"))?;
        Ok(())
    }

    pub async fn auth_failures_since(&self, cutoff: i64) -> Result<Vec<AuthFailure>, String> {
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT id, device_id, surface_key, failure_count, src_ips, observed_at
                 FROM advisory_auth_failure
                 WHERE observed_at >= ?1
                 ORDER BY observed_at DESC",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map(params![cutoff], Self::map_auth_failure)
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))
    }

    pub async fn prune_auth_failures(&self, cutoff: i64) -> Result<usize, String> {
        let db = self.db.lock().await;
        db.execute(
            "DELETE FROM advisory_auth_failure WHERE observed_at < ?1",
            params![cutoff],
        )
        .map_err(|e| format!("prune_auth_failures failed: {e}"))
    }

    fn map_auth_failure(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuthFailure> {
        let src_ips_json: String = row.get(4)?;
        Ok(AuthFailure {
            id: row.get(0)?,
            device_id: row.get(1)?,
            surface_key: row.get(2)?,
            failure_count: row.get(3)?,
            src_ips: serde_json::from_str(&src_ips_json).unwrap_or_default(),
            observed_at: row.get(5)?,
        })
    }
```

(Check how `map_observation` handles the `src_ips` JSON column and mirror its exact error strategy — if it propagates instead of `unwrap_or_default()`, copy that.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ion-drift-storage auth_failure -- --nocapture`
Expected: 2 passed. Then `cargo test -p ion-drift-storage` — full crate still green.

- [ ] **Step 5: Commit**

```bash
git add crates/ion-drift-storage/src/advisory.rs
git commit -m "feat(advisory): auth-failure accumulator accessors on AdvisoryStore"
```

---

### Task 2: Pre-threshold per-service failure totals from the auth scan

**Files:**
- Modify: `crates/ion-drift-web/src/alerting.rs` (scan at `:2044`, `LoginFailure` at `:1289`, `dedup_logging_actions` at `:1402`, `detect_bruteforce` at `:1478` area)

**Interfaces:**
- Consumes: private `LoginFailure { user, src_ip: Option<String>, service, time, prefix }`; `dedup_logging_actions(&[&LoginFailure]) -> Vec<&LoginFailure>`; `detect_bruteforce(&[LoginFailure]) -> Vec<BruteforceSignal>`; `scan_auth_signals_with_cursor(state, poller_id, cursor_key) -> Vec<BruteforceSignal>`.
- Produces (Tasks 3–4 rely on these exact names):
  - `pub(crate) struct ServiceFailureTotal { pub service: String, pub count: usize, pub sources: Vec<String> }`
  - `pub(crate) struct AuthScan { pub signals: Vec<BruteforceSignal>, pub service_totals: Vec<ServiceFailureTotal> }`
  - `scan_auth_signals_with_cursor` is **renamed** to `pub(crate) async fn scan_auth_with_cursor(state, poller_id, cursor_key) -> AuthScan`.

**Why not compute totals from `BruteforceSignal`:** signals exist only above `AUTH_BF_WARN_THRESHOLD` / distributed thresholds, and the per-source and distributed signals deliberately overlap (the sweep's per-service counts include sources that also raised their own signal — see the "Both signals landing in one cycle" comment in `detect_bruteforce`). Summing signals double-counts; thresholding hides exactly the low-and-slow traffic Phase 4 exists to catch. Totals must come from the parsed failures, pre-threshold, sharing the detector's grouping + dedup so the two views of one cycle can never disagree.

- [ ] **Step 1: Write the failing tests** (inside alerting.rs's `#[cfg(test)]` module; `LoginFailure` is in-module so tests construct it directly)

```rust
    fn failure(user: &str, src: Option<&str>, service: &str, time: &str, prefix: &str) -> LoginFailure {
        LoginFailure {
            user: user.to_string(),
            src_ip: src.map(str::to_string),
            service: service.to_string(),
            time: time.to_string(),
            prefix: prefix.to_string(),
        }
    }

    #[test]
    fn service_totals_count_below_threshold_failures() {
        // Two ssh failures from one source: below AUTH_BF_WARN_THRESHOLD, so
        // detect_bruteforce stays silent — but the accumulator must still see 2.
        let failures = vec![
            failure("admin", Some("10.0.0.5"), "ssh", "10:00:00", ""),
            failure("admin", Some("10.0.0.5"), "ssh", "10:03:00", ""),
        ];
        assert!(detect_bruteforce(&failures).is_empty(), "precondition: sub-threshold");
        let totals = service_failure_totals(&failures);
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].service, "ssh");
        assert_eq!(totals[0].count, 2);
        assert_eq!(totals[0].sources, vec!["10.0.0.5"]);
    }

    #[test]
    fn service_totals_collapse_logging_action_duplicates() {
        // One real failure emitted by two /system/logging actions (distinct
        // prefixes) must count once — same dedup the detector applies.
        let failures = vec![
            failure("admin", Some("10.0.0.5"), "api", "10:00:00", ""),
            failure("admin", Some("10.0.0.5"), "api", "10:00:00", "SYS-ERR:"),
        ];
        let totals = service_failure_totals(&failures);
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].count, 1, "logging-action echo is not a second failure");
    }

    #[test]
    fn service_totals_union_sources_and_hide_console() {
        let failures = vec![
            failure("admin", Some("10.0.0.5"), "ssh", "10:00:00", ""),
            failure("admin", Some("10.0.0.2"), "ssh", "10:01:00", ""),
            failure("root", None, "console", "10:02:00", ""),
        ];
        let mut totals = service_failure_totals(&failures);
        totals.sort_by(|a, b| a.service.cmp(&b.service));
        assert_eq!(totals.len(), 2);
        assert_eq!(totals[0].service, "console");
        assert_eq!(totals[0].count, 1, "console failures are counted");
        assert!(totals[0].sources.is_empty(), "…but 'local' is not a source IP");
        assert_eq!(totals[1].service, "ssh");
        assert_eq!(totals[1].count, 2);
        assert_eq!(totals[1].sources, vec!["10.0.0.2", "10.0.0.5"], "sorted, deduped");
    }
```

Note: check the exact `time` format existing alerting tests use for `LoginFailure.time` and match it (any string works for these tests — only `dedup_logging_actions` and same-second grouping read it — but staying consistent keeps the fixture idiom uniform).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ion-drift-web service_totals -- --nocapture`
Expected: FAIL to compile — `service_failure_totals` not found.

- [ ] **Step 3: Implement the pure function** (place next to `detect_bruteforce`)

```rust
/// Per-service deduped failure totals for one scan cycle, thresholds NOT
/// applied. `BruteforceSignal` exists only above the alert thresholds, and the
/// per-source and distributed signals deliberately overlap — so neither one is
/// a usable count. The Phase-4 cross-cycle counter needs the below-threshold
/// failures too, or a low-and-slow run that never crosses a per-cycle
/// threshold stays invisible forever.
#[derive(Debug, PartialEq)]
pub(crate) struct ServiceFailureTotal {
    pub service: String,
    /// Deduped count — same `dedup_logging_actions` pass the detector runs, so
    /// this view and the signal view of one cycle can never disagree about
    /// what a single failure is.
    pub count: usize,
    /// Distinct source IPs, sorted. Console failures count but contribute none.
    pub sources: Vec<String>,
}

fn service_failure_totals(failures: &[LoginFailure]) -> Vec<ServiceFailureTotal> {
    // Identical grouping to detect_bruteforce: (source, service), then the
    // logging-action dedup per group.
    let mut groups: BTreeMap<(String, String), Vec<&LoginFailure>> = BTreeMap::new();
    for f in failures {
        let src = f.src_ip.clone().unwrap_or_else(|| "local".into());
        groups.entry((src, f.service.clone())).or_default().push(f);
    }
    let mut totals: BTreeMap<String, ServiceFailureTotal> = BTreeMap::new();
    for ((src, service), group) in &groups {
        let deduped = dedup_logging_actions(group);
        if deduped.is_empty() {
            continue;
        }
        let entry = totals
            .entry(service.clone())
            .or_insert_with(|| ServiceFailureTotal {
                service: service.clone(),
                count: 0,
                sources: Vec::new(),
            });
        entry.count += deduped.len();
        if src != "local" {
            entry.sources.push(src.clone());
        }
    }
    totals
        .into_values()
        .map(|mut t| {
            t.sources.sort();
            t.sources.dedup();
            t
        })
        .collect()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ion-drift-web service_totals -- --nocapture`
Expected: 3 passed.

- [ ] **Step 5: Return both views from one scan** — rename and rewrap:

```rust
/// Everything one pass over the fresh log entries yields: the thresholded
/// brute-force signals and the pre-threshold per-service totals. One struct so
/// a consumer cannot accidentally run the parse twice against one cursor.
pub(crate) struct AuthScan {
    pub signals: Vec<BruteforceSignal>,
    pub service_totals: Vec<ServiceFailureTotal>,
}
```

Rename `scan_auth_signals_with_cursor` → `scan_auth_with_cursor`, return type `AuthScan`. The body keeps every early return, but each `return Vec::new();` becomes `return AuthScan { signals: Vec::new(), service_totals: Vec::new() };` (add a small `AuthScan::empty()` helper if that reads better), and the final return becomes:

```rust
    AuthScan {
        signals: detect_bruteforce(&parsed),
        service_totals: service_failure_totals(&parsed),
    }
```

(`parsed` is the existing `Vec<LoginFailure>` built at `:2101`. Keep the Drift-own-credential filtering that follows it, if any, applied to `parsed` *before* both calls — read the remainder of the function past line 2104 first and keep both views downstream of the same filtering.)

Update the two call sites:
1. Alert engine (search `scan_auth_signals_with_cursor(` in `alerting.rs`): take `.signals` from the new return.
2. `advisory/exploitation.rs:89` `scan_auth_signals` — Task 3 rewrites it; for this commit change it minimally to `crate::alerting::scan_auth_with_cursor(...).await.signals` so the workspace compiles.

- [ ] **Step 6: Run the full alerting + advisory test suites**

Run: `cargo test -p ion-drift-web alerting && cargo test -p ion-drift-web advisory`
Expected: all pass (behavior above thresholds is unchanged — only the return shape moved).

- [ ] **Step 7: Commit**

```bash
git add crates/ion-drift-web/src/alerting.rs crates/ion-drift-web/src/advisory/exploitation.rs
git commit -m "feat(alerting): pre-threshold per-service failure totals in auth scan"
```

---

### Task 3: `note_auth_failures` — the accumulator's sole writer

**Files:**
- Modify: `crates/ion-drift-web/src/advisory/exploitation.rs`

**Interfaces:**
- Consumes: `crate::alerting::{AuthScan, ServiceFailureTotal, scan_auth_with_cursor}`; `AdvisoryStore::record_auth_failure` (Task 1); existing `surface_key`, `primary_device_id`, `now_unix`, `EXPLOIT_POLLER_ID`, `EXPLOIT_CURSOR_KEY`.
- Produces (Task 4 relies on):
  - `pub async fn scan_auth(state: &AppState) -> AuthScan` (replaces `scan_auth_signals`)
  - `pub async fn note_auth_failures(state: &AppState, totals: &[ServiceFailureTotal]) -> Result<(), String>`

- [ ] **Step 1: Write the failing test** (in exploitation.rs's `#[cfg(test)]`, next to `distributed_observation_uses_per_service_counts`)

```rust
    #[test]
    fn auth_failure_rows_map_services_to_surfaces_and_skip_zero() {
        use crate::alerting::ServiceFailureTotal;
        let totals = vec![
            ServiceFailureTotal {
                service: "ssh".into(),
                count: 3,
                sources: vec!["10.0.0.5".into()],
            },
            ServiceFailureTotal {
                service: "api".into(),
                count: 0,
                sources: Vec::new(),
            },
        ];
        let rows = auth_failure_rows(&totals, "router-1");
        // Zero-count services write no row: absence of a row IS the zero in
        // the windowed-counting convention, same as attack observations.
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "router-1:svc:ssh");
        assert_eq!(rows[0].1, 3);
        assert_eq!(rows[0].2, vec!["10.0.0.5".to_string()]);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p ion-drift-web auth_failure_rows -- --nocapture`
Expected: FAIL to compile — `auth_failure_rows` not found.

- [ ] **Step 3: Implement** (place after `note_observation`; rewrite the `scan_auth_signals` wrapper):

```rust
/// Fetch `/log` through the shared router queue: brute-force signals plus the
/// pre-threshold per-service failure totals, from one cursor advance.
pub async fn scan_auth(state: &AppState) -> crate::alerting::AuthScan {
    crate::alerting::scan_auth_with_cursor(state, EXPLOIT_POLLER_ID, EXPLOIT_CURSOR_KEY).await
}

/// The accumulator rows one cycle's totals turn into: `(surface_key,
/// failure_count, src_ips)` per service. Split out so the mapping is testable
/// without a store behind it, same as `observation_rows`. A service with no
/// failures writes no row — absence of a row is the zero in the
/// windowed-counting convention.
fn auth_failure_rows(
    totals: &[crate::alerting::ServiceFailureTotal],
    device_id: &str,
) -> Vec<(String, i64, Vec<String>)> {
    totals
        .iter()
        .filter(|t| t.count > 0)
        .map(|t| {
            (
                surface_key(device_id, &t.service),
                t.count as i64,
                t.sources.clone(),
            )
        })
        .collect()
}

/// Persist one evaluator cycle's deduped per-surface failure counts into
/// `advisory_auth_failure`. This function is the table's SOLE writer — the
/// cross-cycle counter (Phase 4) only reads. One row per surface per cycle.
pub async fn note_auth_failures(
    state: &AppState,
    totals: &[crate::alerting::ServiceFailureTotal],
) -> Result<(), String> {
    let device_id = primary_device_id(state).await;
    let observed_at = now_unix();
    for (surface, failure_count, src_ips) in auth_failure_rows(totals, &device_id) {
        state
            .advisory_store
            .record_auth_failure(&device_id, &surface, failure_count, &src_ips, observed_at)
            .await?;
    }
    Ok(())
}
```

Delete the now-unused `scan_auth_signals` (Task 2's shim) — Task 4 moves the caller to `scan_auth`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ion-drift-web advisory`
Expected: all pass, including the new `auth_failure_rows_map_services_to_surfaces_and_skip_zero`.

- [ ] **Step 5: Commit**

```bash
git add crates/ion-drift-web/src/advisory/exploitation.rs
git commit -m "feat(advisory): note_auth_failures writes the phase-3 accumulator"
```

---

### Task 4: Evaluator loop wiring + prune

**Files:**
- Modify: `crates/ion-drift-web/src/tasks/advisory.rs`

**Interfaces:**
- Consumes: `exploitation::scan_auth`, `exploitation::note_observation`, `exploitation::note_auth_failures`, `exploitation::evaluate`, `AdvisoryStore::{prune_observations, prune_auth_failures}`.
- Produces: nothing new — this closes the loop.

- [ ] **Step 1: Rewrite the cycle body** in `spawn_advisory_evaluator` (the loop currently at `tasks/advisory.rs:33-55`):

```rust
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
                if let Err(e) = exploitation::note_auth_failures(&state, &scan.service_totals).await
                {
                    tracing::warn!(error = %e, "advisory: auth-failure write failed");
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
```

Retention is the same `OBSERVATION_RETENTION_SECS` (30 days): the accumulator follows the "same windowed counting + prune model as `advisory_attack_observation`" contract written into the v2 migration comment, and Phase 4's window must fit inside whatever is retained.

- [ ] **Step 2: Full workspace verification**

Run: `cargo test --workspace`
Expected: baseline 435 + the 6 new tests (2 storage, 3 alerting, 1 exploitation), 0 failures.

Run: `cargo deny check`
Expected: ok (no new dependencies in this plan).

- [ ] **Step 3: Update the phase marker comment**

In `crates/ion-drift-storage/src/advisory.rs:92`, change `(Phase 3, not wired yet)` to `(Phase 3, wired — see tasks/advisory.rs)` so the schema comment stops claiming the writer is missing.

- [ ] **Step 4: Commit**

```bash
git add crates/ion-drift-web/src/tasks/advisory.rs crates/ion-drift-storage/src/advisory.rs
git commit -m "feat(advisory): evaluator writes + prunes auth-failure accumulator (phase 3)"
```

---

## Out of Scope (Phase 4 — do not build here)

- Cross-cycle counting: reading `auth_failures_since`, windowing across cycles, and promoting sustained low-and-slow totals into exposure/exploitation findings. Phase 3 deliberately ships a writer with no reader beyond tests; Phase 4 decides thresholds and windows.
- Any change to `evaluate()`'s use of `corroborating` signals.
- Any schema change.

## Self-Review Notes

- Spec coverage: v2 migration comment promises "one row per evaluator cycle per surface, deduped count, evaluator is sole writer, same windowed counting + prune model" — Tasks 2–4 deliver each clause; prune delivered in Task 4.
- The one judgment call: totals are computed pre-threshold from parsed failures rather than from signals. Rationale recorded in Task 2 (double-count overlap + threshold blindness). If Scott intended signal-derived counts instead, only Task 2 Step 5 and Task 3 change — storage API is shape-identical either way.
- Type consistency: `ServiceFailureTotal` fields (`service`, `count: usize`, `sources`) used identically in Tasks 2, 3; `record_auth_failure` arity matches between Tasks 1 and 3.
