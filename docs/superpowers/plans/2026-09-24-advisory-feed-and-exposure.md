# Advisory Vulnerability Feed + Exposure Findings — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every managed RouterOS device whose version falls in a published vulnerable range gets a finding automatically (NVD + CISA KEV, no CHS involvement), gated by a mandatory admin consent dialog; bundled service-scoped advisories additionally raise exposure findings.

**Architecture:** A consent-gated daily task pulls NVD (RouterOS CPE) and KEV into `advisory.db` schema v3. The existing 900 s advisory evaluator gains a per-device pass that reads `/system/resource` and `/ip/service` through the router queues, matches versions against stored ranges (`advisory/version.rs`), and reconciles two new finding kinds — `advisory_vulnerable` and `advisory_exposure` — next to the unchanged `advisory_exploitation`. A blocking React dialog records the admin's on/off answer server-side.

**Tech Stack:** Rust 2024 (rustc 1.96) workspace — axum 0.8, rusqlite 0.32, reqwest 0.12 (rustls), tokio; React + TypeScript + TanStack Query, vitest + Testing Library.

**Spec:** `docs/superpowers/specs/2026-09-23-advisory-exposure-findings-design.md` (rev 2, approved 2026-09-24).

## Global Constraints

- Branch `development`; Conventional Commits, imperative, subject ≤ 72 chars. End every commit message with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01TzW8KtcNpg4PChS34Cqp7Z
  ```
- TDD: prove RED before GREEN — run the new test, see it fail for the expected reason, then implement.
- **No new crate or npm dependencies.** Everything needed is already in the workspace (`reqwest`, `serde_json`, `tempfile`, Testing Library).
- Migrations: append-only steps in `MIGRATION_STEPS`, plain `CREATE TABLE` (no `IF NOT EXISTS`), bump `SCHEMA_VERSION` in the same commit (ADR PATTERNS).
- All router and feed input is untrusted: stage through `crate::staging` at the boundary; `CHECK` constraints are the backstop.
- Router reads go **only** through `state.router_queue` (primary) or `state.device_queues` (other RouterOS devices) — never a direct client call.
- Outbound feed hosts are compile-time constants (`services.nvd.nist.gov`, `www.cisa.gov`). No URL is ever read from config, catalog, or request input.
- A failed read or fetch **never** resolves a finding or deletes stored data. Unparseable → "cannot evaluate", never "not affected".
- The advisory evaluator stays the sole writer of advisory findings; the feed task is the sole writer of `feed_*` tables.
- Route registrations stay on **one source line each** (`tests/authz_test.rs` parses them).
- New modules under `advisory/`, `tasks/`, `routes/` register only in their parent `mod.rs` (they are submodules; the `lib.rs`/`main.rs` dual-tree gotcha applies to top-level modules only).
- Do NOT weaken any existing guardrail or test to make a new test pass.
- Verify before claiming done: `cargo test --workspace`, `cargo-deny >= 0.20 check`, `cd web && npx tsc --noEmit && npm test`. Show real output.
- **Host caveat (dev-primary):** `openssl-sys` needs the scratchpad-prefix workaround:
  ```bash
  cd <scratchpad> && apt-get download libssl-dev && dpkg-deb -x libssl-dev_*.deb prefix
  cp prefix/usr/include/x86_64-linux-gnu/openssl/* prefix/usr/include/openssl/
  export OPENSSL_STATIC=1 OPENSSL_LIB_DIR=$PWD/prefix/usr/lib/x86_64-linux-gnu OPENSSL_INCLUDE_DIR=$PWD/prefix/usr/include
  ```

## Deviations from spec rev 2 (deliberate, recorded)

1. **Full daily NVD pull instead of incremental.** The RouterOS CPE query returns 83 CVEs in one request (measured 2026-09-24). A full pull is one request/day, self-heals edited ranges, and removes date-window bookkeeping. Pagination is still handled.
2. **Ranges stored as a JSON column** (`feed_cve.ranges_json`) instead of a `feed_cve_range` table — matches the store's existing JSON-column convention and keeps the storage crate ignorant of the web crate's `VersionRange` type.
3. **Bundled advisories become version findings only when they carry a `version_constraint`.** CVE-2026-16347 (no constraint, service-scoped) is handled by exposure findings only; otherwise every router would get a "version affected" finding for it.
4. **The device pass covers every enabled RouterOS device** (primary + managed switches via `device_queues`), not only the primary router.
5. The escalation note on a reopened exposure finding lives in that cycle's narrative; the next cycle's refresh replaces it. The reopen (status → open, severity → High) is the durable signal.
6. **"Cannot evaluate" is logged, not yet surfaced in the UI.** The spec's device-level "vulnerability status unknown" note needs a device-page surface that does not exist; this turn logs it per device per cycle and never raises or resolves on it. Surfacing it is a follow-on.

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `crates/ion-drift-web/src/advisory/version.rs` | create | RouterOS version parse/order; `VersionRange`; applicability |
| `crates/ion-drift-storage/src/advisory.rs` | modify | schema v3 `feed_cve`/`feed_kev`/`feed_state` + accessors |
| `crates/ion-drift-storage/src/lib.rs` | modify | export `FeedCve`, `FeedKev`, `FeedSourceState` |
| `crates/ion-drift-web/src/advisory/feed.rs` | create | NVD + KEV JSON → staged records (pure, no I/O) |
| `crates/ion-drift-web/src/advisory/consent.rs` | create | consent state in `app_settings` |
| `crates/ion-drift-web/src/tasks/advisory_feed.rs` | create | transport trait, fetch cycle, supervised daily task |
| `crates/ion-drift-web/src/routes/advisory_feed.rs` | create | `GET /api/advisory/feed`, `POST /api/advisory/feed/consent` |
| `crates/ion-drift-web/src/advisory/vulnerable.rs` | create | version findings: assess + reconcile |
| `crates/ion-drift-web/src/advisory/device_pass.rs` | create | per-device reads via queues; drives vulnerable + exposure |
| `crates/ion-drift-web/src/advisory/catalog.rs` | modify | validate `version_constraint` shape |
| `crates/mikrotik-core/src/resources/ip.rs` | modify | `IpService` + `ip_services()` |
| `crates/ion-drift-storage/src/findings.rs` | modify | `reopen_acknowledged_by_key` |
| `crates/ion-drift-web/src/advisory/exposure.rs` | create | exposure findings: assess + reconcile with escalation |
| `crates/ion-drift-web/src/tasks/advisory.rs` | modify | call device pass each cycle |
| `web/src/api/queries/advisory.ts` | create | feed status/consent hooks |
| `web/src/components/advisory-feed-consent.tsx` | create | blocking consent dialog + non-admin banner |
| `web/src/components/advisory-feed-status-banner.tsx` | create | stale/off banner on Findings |
| `web/src/features/settings/settings-advisory-feed.tsx` | create | Settings → Security card |
| `README.md`, `data/advisories/README.md`, `CHANGELOG.md` | modify | outbound-connection disclosure, constraint shape, changelog |

---

## Phase A — Data: versions, storage, feed

### Task 1: RouterOS version matching

**Files:**
- Create: `crates/ion-drift-web/src/advisory/version.rs`
- Modify: `crates/ion-drift-web/src/advisory/mod.rs`

**Interfaces:**
- Produces: `pub(crate) struct RouterOsVersion { .. }` with `pub(crate) fn parse(raw: &str) -> Option<Self>` and `Ord`; `pub(crate) struct VersionRange { pub start_including, pub start_excluding, pub end_including, pub end_excluding, pub exact: Option<String> }` (serde, `deny_unknown_fields`, `Default`); `pub(crate) enum Applicability { Affected, NotAffected, CannotEvaluate }`; `pub(crate) fn evaluate(device_version: &str, ranges: &[VersionRange]) -> (Applicability, Option<&VersionRange>)`.

- [ ] **Step 1: Register the module and write the failing tests**

In `crates/ion-drift-web/src/advisory/mod.rs`, add after `pub mod sustained;`:
```rust
pub mod version;
```

Create `crates/ion-drift-web/src/advisory/version.rs` containing only the tests for now:
```rust
//! RouterOS version parsing and affected-range matching.

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> RouterOsVersion {
        RouterOsVersion::parse(s).unwrap_or_else(|| panic!("failed to parse {s}"))
    }

    fn range(si: Option<&str>, ee: Option<&str>) -> VersionRange {
        VersionRange {
            start_including: si.map(Into::into),
            end_excluding: ee.map(Into::into),
            ..Default::default()
        }
    }

    /// CVE-2026-86060 / CVE-2026-67277 as published by NVD on 2026-09-05.
    fn kev_2026_09() -> Vec<VersionRange> {
        vec![
            range(Some("6.0"), Some("6.49.21")),
            range(Some("7.0"), Some("7.23.4")),
            range(Some("7.24"), Some("7.24.2")),
        ]
    }

    #[test]
    fn parses_router_reported_version_with_channel() {
        assert_eq!(v("7.24.1 (stable)"), v("7.24.1"));
        assert_eq!(v("6.49.20 (long-term)"), v("6.49.20"));
    }

    #[test]
    fn orders_components_numerically_not_lexically() {
        assert!(v("7.24.10") > v("7.24.9"));
        assert!(v("6.49.21") < v("7.0"));
        assert!(v("7.24.1") < v("7.24.2"));
    }

    #[test]
    fn missing_trailing_component_is_zero() {
        assert_eq!(v("7.24"), v("7.24.0"));
    }

    #[test]
    fn pre_releases_order_below_their_release() {
        assert!(v("7.25rc1") < v("7.25"));
        assert!(v("7.25beta3") < v("7.25rc1"));
        assert!(v("7.25rc2") > v("7.25rc1"));
        assert!(v("7.25rc1") > v("7.24.9"));
    }

    #[test]
    fn rejects_garbage() {
        for s in ["", "stable", "7..1", "rc1", "7.24.1.1.1", "7.x", "7.24."] {
            assert!(RouterOsVersion::parse(s).is_none(), "should reject {s:?}");
        }
    }

    #[test]
    fn kev_2026_09_ranges_match_published_fix_points() {
        let r = kev_2026_09();
        for affected in ["7.24.1", "7.24", "7.23.3", "7.0", "6.49.20", "6.0"] {
            assert_eq!(evaluate(affected, &r).0, Applicability::Affected, "{affected}");
        }
        for fixed in ["7.24.2", "7.25", "7.23.4", "7.23.10", "6.49.21", "5.26"] {
            assert_eq!(evaluate(fixed, &r).0, Applicability::NotAffected, "{fixed}");
        }
    }

    #[test]
    fn affected_returns_the_matching_range() {
        let r = kev_2026_09();
        let (_, matched) = evaluate("7.24.1", &r);
        assert_eq!(matched.unwrap().end_excluding.as_deref(), Some("7.24.2"));
    }

    #[test]
    fn unparseable_device_version_cannot_be_evaluated() {
        assert_eq!(evaluate("unknown", &kev_2026_09()).0, Applicability::CannotEvaluate);
    }

    #[test]
    fn empty_range_list_cannot_be_evaluated() {
        assert_eq!(evaluate("7.24.1", &[]).0, Applicability::CannotEvaluate);
    }

    #[test]
    fn unparseable_bound_withholds_the_all_clear() {
        let r = vec![range(Some("7.0"), Some("seven"))];
        assert_eq!(evaluate("7.1", &r).0, Applicability::CannotEvaluate);
    }

    #[test]
    fn unparseable_bound_does_not_mask_a_real_match() {
        let r = vec![range(Some("7.0"), Some("seven")), range(Some("7.0"), Some("7.24.2"))];
        assert_eq!(evaluate("7.1", &r).0, Applicability::Affected);
    }

    #[test]
    fn boundless_range_matches_every_version() {
        assert_eq!(evaluate("7.1", &[VersionRange::default()]).0, Applicability::Affected);
    }

    #[test]
    fn exact_version_matches_only_itself() {
        let r = vec![VersionRange { exact: Some("6.42".into()), ..Default::default() }];
        assert_eq!(evaluate("6.42", &r).0, Applicability::Affected);
        assert_eq!(evaluate("6.42.1", &r).0, Applicability::NotAffected);
    }

    #[test]
    fn inclusive_and_exclusive_bounds() {
        let end_incl = vec![VersionRange { end_including: Some("6.42".into()), ..Default::default() }];
        assert_eq!(evaluate("6.42", &end_incl).0, Applicability::Affected);
        assert_eq!(evaluate("6.42.1", &end_incl).0, Applicability::NotAffected);
        let start_excl = vec![VersionRange { start_excluding: Some("6.0".into()), ..Default::default() }];
        assert_eq!(evaluate("6.0", &start_excl).0, Applicability::NotAffected);
        assert_eq!(evaluate("6.0.1", &start_excl).0, Applicability::Affected);
    }

    #[test]
    fn range_json_round_trips_and_rejects_unknown_fields() {
        let r: Vec<VersionRange> =
            serde_json::from_str(r#"[{"start_including":"7.0","end_excluding":"7.23.4"}]"#).unwrap();
        assert_eq!(r[0].end_excluding.as_deref(), Some("7.23.4"));
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"[{"start_including":"7.0","end_excluding":"7.23.4"}]"#
        );
        assert!(serde_json::from_str::<Vec<VersionRange>>(r#"[{"lt":"7.16"}]"#).is_err());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ion-drift-web advisory::version`
Expected: compile FAIL — `cannot find type RouterOsVersion`, `VersionRange`, `evaluate`, `Applicability`.

- [ ] **Step 3: Implement**

Insert above the `#[cfg(test)]` block in `version.rs`:
```rust
//!
//! Advisory applicability is decided here and nowhere else. The rules are
//! conservative on purpose: anything that cannot be parsed is
//! [`Applicability::CannotEvaluate`], never "not affected", so a malformed feed
//! record or an unexpected version string can only withhold a claim — it can
//! never produce a false all-clear.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

/// Pre-release channel. Orders below the release it precedes; beta < rc.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PreRelease {
    Beta(u32),
    Rc(u32),
}

/// A RouterOS version: numeric components plus an optional pre-release tag.
/// Equality and ordering treat missing trailing components as zero, so
/// `7.24 == 7.24.0`.
#[derive(Clone, Debug)]
pub(crate) struct RouterOsVersion {
    parts: Vec<u32>,
    pre: Option<PreRelease>,
}

/// RouterOS uses at most three components; four leaves headroom, more is garbage.
const MAX_COMPONENTS: usize = 4;

impl RouterOsVersion {
    /// Parse `7.24.1`, `7.24.1 (stable)`, `7.25rc1`, `7.25beta2`.
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        let token = raw.split_whitespace().next()?;
        let (numeric, pre) = split_pre_release(token)?;
        let parts = numeric
            .split('.')
            .map(|p| p.parse::<u32>().ok())
            .collect::<Option<Vec<u32>>>()?;
        if parts.is_empty() || parts.len() > MAX_COMPONENTS {
            return None;
        }
        Some(Self { parts, pre })
    }
}

fn split_pre_release(token: &str) -> Option<(&str, Option<PreRelease>)> {
    let tags: [(&str, fn(u32) -> PreRelease); 2] =
        [("beta", PreRelease::Beta), ("rc", PreRelease::Rc)];
    for (tag, make) in tags {
        if let Some(at) = token.find(tag) {
            let digits = &token[at + tag.len()..];
            let n = if digits.is_empty() { 0 } else { digits.parse::<u32>().ok()? };
            return Some((&token[..at], Some(make(n))));
        }
    }
    Some((token, None))
}

impl Ord for RouterOsVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        let len = self.parts.len().max(other.parts.len());
        for i in 0..len {
            let a = self.parts.get(i).copied().unwrap_or(0);
            let b = other.parts.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                Ordering::Equal => {}
                unequal => return unequal,
            }
        }
        match (self.pre, other.pre) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => a.cmp(&b),
        }
    }
}

impl PartialOrd for RouterOsVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for RouterOsVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for RouterOsVersion {}

/// One affected range, in the shape shared by the NVD feed and the bundled
/// catalog. Every bound is optional. A range with no bounds and no `exact`
/// matches every version (NVD's wildcard CPE match).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VersionRange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_including: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_excluding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_including: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_excluding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Applicability {
    Affected,
    NotAffected,
    CannotEvaluate,
}

impl VersionRange {
    /// `None` when a bound in this range cannot be parsed.
    fn contains(&self, v: &RouterOsVersion) -> Option<bool> {
        if let Some(exact) = &self.exact {
            return Some(*v == RouterOsVersion::parse(exact)?);
        }
        let bound = |b: &Option<String>| -> Option<Option<RouterOsVersion>> {
            match b {
                None => Some(None),
                Some(s) => RouterOsVersion::parse(s).map(Some),
            }
        };
        let start_incl = bound(&self.start_including)?;
        let start_excl = bound(&self.start_excluding)?;
        let end_incl = bound(&self.end_including)?;
        let end_excl = bound(&self.end_excluding)?;
        Some(
            start_incl.is_none_or(|b| *v >= b)
                && start_excl.is_none_or(|b| *v > b)
                && end_incl.is_none_or(|b| *v <= b)
                && end_excl.is_none_or(|b| *v < b),
        )
    }
}

/// Decide whether `device_version` falls in any of `ranges`.
///
/// Returns the first matching range when affected, so callers can derive the
/// fix point. An empty range list is `CannotEvaluate` — "no data" must never
/// read as "not affected".
pub(crate) fn evaluate<'a>(
    device_version: &str,
    ranges: &'a [VersionRange],
) -> (Applicability, Option<&'a VersionRange>) {
    let Some(v) = RouterOsVersion::parse(device_version) else {
        return (Applicability::CannotEvaluate, None);
    };
    if ranges.is_empty() {
        return (Applicability::CannotEvaluate, None);
    }
    let mut unknown = false;
    for r in ranges {
        match r.contains(&v) {
            Some(true) => return (Applicability::Affected, Some(r)),
            Some(false) => {}
            None => unknown = true,
        }
    }
    if unknown {
        (Applicability::CannotEvaluate, None)
    } else {
        (Applicability::NotAffected, None)
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ion-drift-web advisory::version`
Expected: 15 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ion-drift-web/src/advisory/version.rs crates/ion-drift-web/src/advisory/mod.rs
git commit -m "feat(advisory): RouterOS version parsing and range matching"
```

---

### Task 2: `advisory.db` schema v3 — feed tables

**Files:**
- Modify: `crates/ion-drift-storage/src/advisory.rs` (types after `AuthFailure` ~line 85; `SCHEMA_VERSION` line 96; `MIGRATION_STEPS` lines 110-125; new methods after `list_advisories`; tests module)
- Modify: `crates/ion-drift-storage/src/lib.rs:11`

**Interfaces:**
- Produces: `pub struct FeedCve { cve_id, published, last_modified, description: String, cvss_version: Option<String>, cvss_score: Option<f64>, cvss_vector: Option<String>, cwe: Option<String>, nvd_status: String, ranges_json: String }`; `pub struct FeedKev { cve_id, date_added: String, due_date: Option<String> }`; `pub struct FeedSourceState { source: String, last_success_at: Option<i64>, last_attempt_at: i64, last_error: Option<String>, records: i64 }`; on `AdvisoryStore`: `replace_feed_cves(&self, &[FeedCve], now: i64) -> Result<usize, String>`, `replace_feed_kev(&self, &[FeedKev], now: i64) -> Result<usize, String>`, `list_feed_cves(&self) -> Result<Vec<FeedCve>, String>`, `list_feed_kev(&self) -> Result<Vec<FeedKev>, String>`, `record_feed_attempt(&self, source: &str, now: i64, outcome: Result<i64, &str>) -> Result<(), String>`, `feed_states(&self) -> Result<Vec<FeedSourceState>, String>`. `SCHEMA_VERSION = 3`.

- [ ] **Step 1: Write the failing tests**

Append inside `mod tests` in `crates/ion-drift-storage/src/advisory.rs`:
```rust
    fn feed_cve(id: &str) -> FeedCve {
        FeedCve {
            cve_id: id.to_string(),
            published: "2026-09-05T00:00:00.000".into(),
            last_modified: "2026-09-10T00:00:00.000".into(),
            description: "desc".into(),
            cvss_version: Some("4.0".into()),
            cvss_score: Some(9.2),
            cvss_vector: Some("CVSS:4.0/AV:N".into()),
            cwe: Some("CWE-88".into()),
            nvd_status: "Analyzed".into(),
            ranges_json: r#"[{"start_including":"7.0","end_excluding":"7.23.4"}]"#.into(),
        }
    }

    fn ids(cves: &[FeedCve]) -> Vec<String> {
        cves.iter().map(|c| c.cve_id.clone()).collect()
    }

    #[tokio::test]
    async fn replace_feed_cves_swaps_the_whole_set() {
        let f = NamedTempFile::new().unwrap();
        let store = AdvisoryStore::new(f.path()).await.unwrap();
        store.replace_feed_cves(&[feed_cve("CVE-2018-14847"), feed_cve("CVE-2026-86060")], 1).await.unwrap();
        store.replace_feed_cves(&[feed_cve("CVE-2026-86060"), feed_cve("CVE-2026-67277")], 2).await.unwrap();
        assert_eq!(ids(&store.list_feed_cves().await.unwrap()), vec!["CVE-2026-67277", "CVE-2026-86060"]);
    }

    #[tokio::test]
    async fn replace_feed_cves_refuses_an_empty_set_and_keeps_data() {
        let f = NamedTempFile::new().unwrap();
        let store = AdvisoryStore::new(f.path()).await.unwrap();
        store.replace_feed_cves(&[feed_cve("CVE-2026-86060")], 1).await.unwrap();
        assert!(store.replace_feed_cves(&[], 2).await.is_err());
        assert_eq!(ids(&store.list_feed_cves().await.unwrap()), vec!["CVE-2026-86060"]);
    }

    #[tokio::test]
    async fn failed_replace_rolls_back_to_prior_data() {
        let f = NamedTempFile::new().unwrap();
        let store = AdvisoryStore::new(f.path()).await.unwrap();
        store.replace_feed_cves(&[feed_cve("CVE-2026-86060")], 1).await.unwrap();
        // Duplicate primary key mid-batch: the whole replace must roll back.
        let dup = [feed_cve("CVE-2026-67277"), feed_cve("CVE-2026-67277")];
        assert!(store.replace_feed_cves(&dup, 2).await.is_err());
        assert_eq!(ids(&store.list_feed_cves().await.unwrap()), vec!["CVE-2026-86060"]);
    }

    #[tokio::test]
    async fn check_constraint_rejects_oversized_description() {
        let f = NamedTempFile::new().unwrap();
        let store = AdvisoryStore::new(f.path()).await.unwrap();
        let mut big = feed_cve("CVE-2026-86060");
        big.description = "x".repeat(4001);
        assert!(store.replace_feed_cves(&[big], 1).await.is_err());
    }

    #[tokio::test]
    async fn replace_feed_kev_round_trips_and_refuses_empty() {
        let f = NamedTempFile::new().unwrap();
        let store = AdvisoryStore::new(f.path()).await.unwrap();
        let kev = FeedKev { cve_id: "CVE-2026-86060".into(), date_added: "2026-09-10".into(), due_date: Some("2026-10-01".into()) };
        store.replace_feed_kev(std::slice::from_ref(&kev), 1).await.unwrap();
        assert!(store.replace_feed_kev(&[], 2).await.is_err());
        assert_eq!(store.list_feed_kev().await.unwrap(), vec![kev]);
    }

    #[tokio::test]
    async fn feed_attempt_failure_keeps_last_success() {
        let f = NamedTempFile::new().unwrap();
        let store = AdvisoryStore::new(f.path()).await.unwrap();
        store.record_feed_attempt("nvd", 100, Ok(5)).await.unwrap();
        store.record_feed_attempt("nvd", 200, Err("HTTP 503")).await.unwrap();
        let states = store.feed_states().await.unwrap();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].last_success_at, Some(100));
        assert_eq!(states[0].last_attempt_at, 200);
        assert_eq!(states[0].last_error.as_deref(), Some("HTTP 503"));
        assert_eq!(states[0].records, 5);
    }

    #[tokio::test]
    async fn feed_state_rejects_unknown_source() {
        let f = NamedTempFile::new().unwrap();
        let store = AdvisoryStore::new(f.path()).await.unwrap();
        assert!(store.record_feed_attempt("evil", 1, Ok(1)).await.is_err());
    }

    #[tokio::test]
    async fn v2_database_migrates_to_v3() {
        let f = NamedTempFile::new().unwrap();
        {
            let _ = AdvisoryStore::new(f.path()).await.unwrap();
        }
        {
            // Rewind the throwaway temp database to v2: remove the v3 tables and the stamp.
            let c = Connection::open(f.path()).unwrap();
            c.execute_batch(
                "DROP TABLE feed_cve; DROP TABLE feed_kev; DROP TABLE feed_state;
                 PRAGMA user_version = 2;",
            )
            .unwrap();
        }
        let store = AdvisoryStore::new(f.path()).await.unwrap();
        store.replace_feed_cves(&[feed_cve("CVE-2026-86060")], 1).await.unwrap();
        let c = Connection::open(f.path()).unwrap();
        let version: u32 = c.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(version, 3);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ion-drift-storage advisory::tests`
Expected: compile FAIL — `cannot find struct FeedCve`, `no method named replace_feed_cves`.

- [ ] **Step 3: Implement**

(a) Add the types after `pub struct AuthFailure { .. }`:
```rust
/// One RouterOS CVE as fetched from NVD, already staged by the web crate.
/// `ranges_json` is the affected-version list in the web crate's
/// `VersionRange` shape; storage keeps it opaque, like the catalog's other
/// JSON columns. Sole writer: the advisory feed task.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FeedCve {
    pub cve_id: String,
    pub published: String,
    pub last_modified: String,
    pub description: String,
    pub cvss_version: Option<String>,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub cwe: Option<String>,
    pub nvd_status: String,
    pub ranges_json: String,
}

/// One CISA Known Exploited Vulnerabilities entry for a MikroTik product.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedKev {
    pub cve_id: String,
    pub date_added: String,
    pub due_date: Option<String>,
}

/// Health of one feed source (`"nvd"` or `"kev"`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedSourceState {
    pub source: String,
    pub last_success_at: Option<i64>,
    pub last_attempt_at: i64,
    pub last_error: Option<String>,
    pub records: i64,
}
```

(b) Change `pub const SCHEMA_VERSION: u32 = 2;` to `3`, extend its doc comment with: `v3 adds the vulnerability feed tables (feed_cve, feed_kev, feed_state).`

(c) Replace the `MIGRATION_STEPS` array so it holds both steps (the v2 step text is unchanged):
```rust
    const MIGRATION_STEPS: &'static [(u32, &'static str)] = &[
        (
            2,
            "
        CREATE TABLE advisory_auth_failure (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            surface_key TEXT NOT NULL,
            failure_count INTEGER NOT NULL,
            src_ips TEXT NOT NULL,
            observed_at INTEGER NOT NULL
        );

        CREATE INDEX idx_advisory_auth_failure_surface
            ON advisory_auth_failure(surface_key, observed_at DESC);
        ",
        ),
        // v3 — vulnerability feed. The CHECK constraints are the backstop
        // behind the web crate's staging layer: a future writer that bypasses
        // staging still cannot store unbounded third-party text.
        (
            3,
            "
        CREATE TABLE feed_cve (
            cve_id TEXT PRIMARY KEY CHECK (length(cve_id) BETWEEN 9 AND 32),
            published TEXT NOT NULL CHECK (length(published) <= 40),
            last_modified TEXT NOT NULL CHECK (length(last_modified) <= 40),
            description TEXT NOT NULL CHECK (length(description) <= 4000),
            cvss_version TEXT CHECK (cvss_version IS NULL OR length(cvss_version) <= 8),
            cvss_score REAL CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)),
            cvss_vector TEXT CHECK (cvss_vector IS NULL OR length(cvss_vector) <= 256),
            cwe TEXT CHECK (cwe IS NULL OR length(cwe) <= 64),
            nvd_status TEXT NOT NULL CHECK (length(nvd_status) <= 40),
            ranges_json TEXT NOT NULL CHECK (length(ranges_json) <= 16384),
            fetched_at INTEGER NOT NULL
        );

        CREATE TABLE feed_kev (
            cve_id TEXT PRIMARY KEY CHECK (length(cve_id) BETWEEN 9 AND 32),
            date_added TEXT NOT NULL CHECK (length(date_added) <= 40),
            due_date TEXT CHECK (due_date IS NULL OR length(due_date) <= 40),
            fetched_at INTEGER NOT NULL
        );

        CREATE TABLE feed_state (
            source TEXT PRIMARY KEY CHECK (source IN ('nvd', 'kev')),
            last_success_at INTEGER,
            last_attempt_at INTEGER NOT NULL,
            last_error TEXT CHECK (last_error IS NULL OR length(last_error) <= 512),
            records INTEGER NOT NULL DEFAULT 0
        );
        ",
        ),
    ];
```

(d) Add methods inside `impl AdvisoryStore`, after `list_advisories`:
```rust
    /// Replace the stored NVD set with a freshly fetched one, atomically.
    ///
    /// Refuses an empty set: a fetch that parsed cleanly but returned nothing
    /// is far more likely an upstream fault than MikroTik having no CVEs, and
    /// accepting it would silently clear every vulnerability finding. Any
    /// insert failure rolls the whole replace back, keeping the prior set.
    pub async fn replace_feed_cves(&self, cves: &[FeedCve], now: i64) -> Result<usize, String> {
        if cves.is_empty() {
            return Err("refusing to replace the NVD set with an empty one".to_string());
        }
        let mut db = self.db.lock().await;
        let tx = db.transaction().map_err(|e| format!("begin feed_cve replace: {e}"))?;
        tx.execute("DELETE FROM feed_cve", [])
            .map_err(|e| format!("clear feed_cve: {e}"))?;
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO feed_cve (cve_id, published, last_modified, description,
                        cvss_version, cvss_score, cvss_vector, cwe, nvd_status, ranges_json,
                        fetched_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                )
                .map_err(|e| format!("prepare feed_cve insert: {e}"))?;
            for c in cves {
                stmt.execute(params![
                    c.cve_id, c.published, c.last_modified, c.description, c.cvss_version,
                    c.cvss_score, c.cvss_vector, c.cwe, c.nvd_status, c.ranges_json, now
                ])
                .map_err(|e| format!("insert {}: {e}", c.cve_id))?;
            }
        }
        tx.commit().map_err(|e| format!("commit feed_cve replace: {e}"))?;
        Ok(cves.len())
    }

    /// Replace the stored KEV set, atomically. Refuses an empty set for the
    /// same reason as [`Self::replace_feed_cves`].
    pub async fn replace_feed_kev(&self, kev: &[FeedKev], now: i64) -> Result<usize, String> {
        if kev.is_empty() {
            return Err("refusing to replace the KEV set with an empty one".to_string());
        }
        let mut db = self.db.lock().await;
        let tx = db.transaction().map_err(|e| format!("begin feed_kev replace: {e}"))?;
        tx.execute("DELETE FROM feed_kev", [])
            .map_err(|e| format!("clear feed_kev: {e}"))?;
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO feed_kev (cve_id, date_added, due_date, fetched_at)
                     VALUES (?1, ?2, ?3, ?4)",
                )
                .map_err(|e| format!("prepare feed_kev insert: {e}"))?;
            for k in kev {
                stmt.execute(params![k.cve_id, k.date_added, k.due_date, now])
                    .map_err(|e| format!("insert kev {}: {e}", k.cve_id))?;
            }
        }
        tx.commit().map_err(|e| format!("commit feed_kev replace: {e}"))?;
        Ok(kev.len())
    }

    pub async fn list_feed_cves(&self) -> Result<Vec<FeedCve>, String> {
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT cve_id, published, last_modified, description, cvss_version,
                        cvss_score, cvss_vector, cwe, nvd_status, ranges_json
                 FROM feed_cve ORDER BY cve_id",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(FeedCve {
                    cve_id: r.get(0)?,
                    published: r.get(1)?,
                    last_modified: r.get(2)?,
                    description: r.get(3)?,
                    cvss_version: r.get(4)?,
                    cvss_score: r.get(5)?,
                    cvss_vector: r.get(6)?,
                    cwe: r.get(7)?,
                    nvd_status: r.get(8)?,
                    ranges_json: r.get(9)?,
                })
            })
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))
    }

    pub async fn list_feed_kev(&self) -> Result<Vec<FeedKev>, String> {
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare("SELECT cve_id, date_added, due_date FROM feed_kev ORDER BY cve_id")
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(FeedKev { cve_id: r.get(0)?, date_added: r.get(1)?, due_date: r.get(2)? })
            })
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))
    }

    /// Record the outcome of one fetch attempt for `source`. A failure updates
    /// the attempt time and error but never touches `last_success_at` or
    /// `records`, so staleness is measured from the last good fetch.
    pub async fn record_feed_attempt(
        &self,
        source: &str,
        now: i64,
        outcome: Result<i64, &str>,
    ) -> Result<(), String> {
        let db = self.db.lock().await;
        match outcome {
            Ok(records) => db.execute(
                "INSERT INTO feed_state (source, last_success_at, last_attempt_at, last_error, records)
                 VALUES (?1, ?2, ?2, NULL, ?3)
                 ON CONFLICT(source) DO UPDATE SET
                    last_success_at = ?2, last_attempt_at = ?2, last_error = NULL, records = ?3",
                params![source, now, records],
            ),
            Err(error) => {
                let error: String = error.chars().take(512).collect();
                db.execute(
                    "INSERT INTO feed_state (source, last_success_at, last_attempt_at, last_error, records)
                     VALUES (?1, NULL, ?2, ?3, 0)
                     ON CONFLICT(source) DO UPDATE SET last_attempt_at = ?2, last_error = ?3",
                    params![source, now, error],
                )
            }
        }
        .map_err(|e| format!("record feed attempt: {e}"))?;
        Ok(())
    }

    pub async fn feed_states(&self) -> Result<Vec<FeedSourceState>, String> {
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT source, last_success_at, last_attempt_at, last_error, records
                 FROM feed_state ORDER BY source",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(FeedSourceState {
                    source: r.get(0)?,
                    last_success_at: r.get(1)?,
                    last_attempt_at: r.get(2)?,
                    last_error: r.get(3)?,
                    records: r.get(4)?,
                })
            })
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))
    }
```
If `params` is not already imported at the top of `advisory.rs`, add `use rusqlite::params;` (check with `grep -n 'params' crates/ion-drift-storage/src/advisory.rs | head -3`).

(e) In `crates/ion-drift-storage/src/lib.rs` change line 11 to:
```rust
pub use advisory::{AdvisoryRecord, AdvisoryStore, AttackObservation, FeedCve, FeedKev, FeedSourceState};
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p ion-drift-storage advisory`
Expected: all new tests pass. If a pre-existing test asserts the literal `user_version` `2` (find with `grep -n 'user_version' crates/ion-drift-storage/src/advisory.rs`), change the literal to `AdvisoryStore::SCHEMA_VERSION` — that is a version-bump consequence, not a weakened test. Any other pre-existing failure: stop and investigate.

- [ ] **Step 5: Commit**

```bash
git add crates/ion-drift-storage/src/advisory.rs crates/ion-drift-storage/src/lib.rs
git commit -m "feat(storage): advisory.db v3 adds vulnerability feed tables"
```

---

### Task 3: NVD + KEV parsing

**Files:**
- Create: `crates/ion-drift-web/src/advisory/feed.rs`
- Modify: `crates/ion-drift-web/src/advisory/mod.rs`

**Interfaces:**
- Consumes: `VersionRange` (Task 1); `FeedCve`, `FeedKev` (Task 2); `crate::staging::stage_text(raw: &str, max: usize) -> String`.
- Produces: `pub(crate) const MAX_BODY_BYTES: usize`; `pub(crate) struct NvdPage { pub total_results: u64, pub start_index: u64, pub results_per_page: u64, pub cves: Vec<FeedCve>, pub skipped: usize }`; `pub(crate) fn parse_nvd(body: &[u8]) -> Result<NvdPage, String>`; `pub(crate) fn parse_kev(body: &[u8]) -> Result<Vec<FeedKev>, String>`; `pub(crate) fn is_cve_id(s: &str) -> bool`; `#[cfg(test)] pub(crate) mod fixtures { pub(crate) fn nvd_body() -> Vec<u8>; pub(crate) fn kev_body() -> Vec<u8>; }`.

- [ ] **Step 1: Register the module and write the failing tests**

In `advisory/mod.rs` add `pub mod feed;`.

Create `crates/ion-drift-web/src/advisory/feed.rs`:
```rust
//! NVD and CISA KEV feed parsing.

#[cfg(test)]
pub(crate) mod fixtures {
    /// One page shaped like NVD API 2.0: CVE-2026-86060 as published
    /// 2026-09-05, a CVE for another product, a malformed id, and an item
    /// with no `cve` object.
    pub(crate) fn nvd_body() -> Vec<u8> {
        serde_json::json!({
            "resultsPerPage": 4, "startIndex": 0, "totalResults": 4,
            "vulnerabilities": [
                { "cve": {
                    "id": "CVE-2026-86060",
                    "published": "2026-09-05T15:15:00.000",
                    "lastModified": "2026-09-10T20:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        { "lang": "es", "value": "no" },
                        { "lang": "en", "value": "RouterOS contains an argument-handling flaw in the SSH login path." }
                    ],
                    "metrics": { "cvssMetricV40": [ { "cvssData": {
                        "version": "4.0", "baseScore": 9.2,
                        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                    } } ] },
                    "weaknesses": [ { "description": [ { "lang": "en", "value": "CWE-88" } ] } ],
                    "configurations": [ { "nodes": [ { "cpeMatch": [
                        { "vulnerable": true, "criteria": "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
                          "versionStartIncluding": "6.0", "versionEndExcluding": "6.49.21" },
                        { "vulnerable": true, "criteria": "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
                          "versionStartIncluding": "7.0", "versionEndExcluding": "7.23.4" },
                        { "vulnerable": true, "criteria": "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
                          "versionStartIncluding": "7.24", "versionEndExcluding": "7.24.2" },
                        { "vulnerable": false, "criteria": "cpe:2.3:h:mikrotik:rb4011:-:*:*:*:*:*:*:*" }
                    ] } ] } ]
                } },
                { "cve": {
                    "id": "CVE-2026-11111",
                    "configurations": [ { "nodes": [ { "cpeMatch": [
                        { "vulnerable": true, "criteria": "cpe:2.3:o:other:thing:*:*:*:*:*:*:*:*",
                          "versionEndExcluding": "1.0" }
                    ] } ] } ]
                } },
                { "cve": { "id": "not-a-cve" } },
                { "unexpected": true }
            ]
        })
        .to_string()
        .into_bytes()
    }

    pub(crate) fn kev_body() -> Vec<u8> {
        serde_json::json!({
            "catalogVersion": "2026.09.23", "count": 3,
            "vulnerabilities": [
                { "cveID": "CVE-2026-86060", "vendorProject": "MikroTik", "product": "RouterOS",
                  "dateAdded": "2026-09-10", "dueDate": "2026-10-01" },
                { "cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j",
                  "dateAdded": "2021-12-10" },
                { "cveID": "bogus", "vendorProject": "MikroTik", "dateAdded": "2026-01-01" }
            ]
        })
        .to_string()
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::version::VersionRange;

    fn ranges_of(c: &ion_drift_storage::FeedCve) -> Vec<VersionRange> {
        serde_json::from_str(&c.ranges_json).unwrap()
    }

    #[test]
    fn parses_published_ranges_for_cve_2026_86060() {
        let page = parse_nvd(&fixtures::nvd_body()).unwrap();
        assert_eq!(page.cves.len(), 1);
        let c = &page.cves[0];
        assert_eq!(c.cve_id, "CVE-2026-86060");
        assert_eq!(c.cvss_score, Some(9.2));
        assert_eq!(c.cwe.as_deref(), Some("CWE-88"));
        assert!(c.description.starts_with("RouterOS contains"));
        let r = ranges_of(c);
        assert_eq!(r.len(), 3);
        assert_eq!(r[2].start_including.as_deref(), Some("7.24"));
        assert_eq!(r[2].end_excluding.as_deref(), Some("7.24.2"));
    }

    #[test]
    fn counts_skipped_records_and_keeps_the_rest() {
        let page = parse_nvd(&fixtures::nvd_body()).unwrap();
        assert_eq!(page.skipped, 3);
        assert_eq!(page.total_results, 4);
    }

    #[test]
    fn rejects_oversized_body() {
        let body = vec![b' '; MAX_BODY_BYTES + 1];
        assert!(parse_nvd(&body).unwrap_err().contains("too large"));
        assert!(parse_kev(&body).unwrap_err().contains("too large"));
    }

    #[test]
    fn rejects_non_json() {
        assert!(parse_nvd(b"<html>rate limited</html>").is_err());
    }

    #[test]
    fn stages_hostile_description() {
        let hostile = format!("\u{202E}evil{}", "A".repeat(10_000));
        let body = serde_json::json!({
            "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
            "vulnerabilities": [ { "cve": {
                "id": "CVE-2026-86060",
                "descriptions": [ { "lang": "en", "value": hostile } ],
                "configurations": [ { "nodes": [ { "cpeMatch": [
                    { "vulnerable": true, "criteria": "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
                      "versionEndExcluding": "7.24.2" } ] } ] } ]
            } } ]
        })
        .to_string();
        let page = parse_nvd(body.as_bytes()).unwrap();
        let d = &page.cves[0].description;
        assert!(!d.contains('\u{202E}'));
        assert!(d.chars().count() <= 4000);
    }

    #[test]
    fn dash_version_without_bounds_is_not_a_wildcard() {
        let body = serde_json::json!({
            "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
            "vulnerabilities": [ { "cve": {
                "id": "CVE-2026-22222",
                "configurations": [ { "nodes": [ { "cpeMatch": [
                    { "vulnerable": true, "criteria": "cpe:2.3:o:mikrotik:routeros:-:*:*:*:*:*:*:*" }
                ] } ] } ]
            } } ]
        })
        .to_string();
        let page = parse_nvd(body.as_bytes()).unwrap();
        assert!(page.cves.is_empty(), "N/A version must not become 'every version affected'");
    }

    #[test]
    fn kev_keeps_only_mikrotik_entries_with_valid_ids() {
        let kev = parse_kev(&fixtures::kev_body()).unwrap();
        assert_eq!(kev.len(), 1);
        assert_eq!(kev[0].cve_id, "CVE-2026-86060");
        assert_eq!(kev[0].date_added, "2026-09-10");
        assert_eq!(kev[0].due_date.as_deref(), Some("2026-10-01"));
    }

    #[test]
    fn cve_id_validation() {
        for ok in ["CVE-2018-14847", "CVE-2026-86060", "CVE-2026-1234567"] {
            assert!(is_cve_id(ok), "{ok}");
        }
        for bad in ["CVE-18-14847", "cve-2018-14847", "CVE-2018-123", "CVE-2018-14847x", "not-a-cve", ""] {
            assert!(!is_cve_id(bad), "{bad}");
        }
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ion-drift-web advisory::feed`
Expected: compile FAIL — `cannot find function parse_nvd`, `MAX_BODY_BYTES`, `is_cve_id`.

- [ ] **Step 3: Implement**

Insert above `#[cfg(test)] pub(crate) mod fixtures` in `feed.rs`:
```rust
//!
//! Everything here is untrusted third-party input. Parsing is lenient about
//! shape (unknown fields ignored, missing optionals tolerated, one bad record
//! never sinks the page) and strict about content: every string is staged and
//! bounded, CVE ids are validated, and a record that fails any of that is
//! skipped and counted rather than stored. Nothing in this module does I/O.

use std::collections::BTreeSet;

use ion_drift_storage::{FeedCve, FeedKev};
use serde::Deserialize;

use crate::advisory::version::VersionRange;
use crate::staging::stage_text;

/// Hard ceiling on a feed response. The RouterOS NVD set is ~0.5 MB and the
/// full KEV catalog ~1.5 MB (2026-09); 16 MB is headroom, not a target.
pub(crate) const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_DESCRIPTION: usize = 4000;
const MAX_VERSION: usize = 32;
const MAX_RANGES: usize = 64;
const ROUTEROS_CPE_PREFIX: &str = "cpe:2.3:o:mikrotik:routeros:";

#[derive(Debug)]
pub(crate) struct NvdPage {
    pub total_results: u64,
    pub start_index: u64,
    pub results_per_page: u64,
    pub cves: Vec<FeedCve>,
    /// Records dropped: malformed, invalid id, duplicate, or no RouterOS range.
    pub skipped: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdResponse {
    #[serde(default)]
    results_per_page: u64,
    #[serde(default)]
    start_index: u64,
    #[serde(default)]
    total_results: u64,
    /// Kept as raw values so one malformed record is skipped, not fatal.
    #[serde(default)]
    vulnerabilities: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCve {
    id: String,
    #[serde(default)]
    published: String,
    #[serde(default)]
    last_modified: String,
    #[serde(default)]
    vuln_status: String,
    #[serde(default)]
    descriptions: Vec<LangValue>,
    #[serde(default)]
    metrics: NvdMetrics,
    #[serde(default)]
    weaknesses: Vec<NvdWeakness>,
    #[serde(default)]
    configurations: Vec<NvdConfiguration>,
}

#[derive(Deserialize)]
struct LangValue {
    lang: String,
    value: String,
}

#[derive(Deserialize, Default)]
struct NvdMetrics {
    #[serde(default, rename = "cvssMetricV40")]
    v40: Vec<NvdMetric>,
    #[serde(default, rename = "cvssMetricV31")]
    v31: Vec<NvdMetric>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdMetric {
    cvss_data: CvssData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssData {
    #[serde(default)]
    version: String,
    base_score: f64,
    #[serde(default)]
    vector_string: String,
}

#[derive(Deserialize)]
struct NvdWeakness {
    #[serde(default)]
    description: Vec<LangValue>,
}

#[derive(Deserialize)]
struct NvdConfiguration {
    #[serde(default)]
    nodes: Vec<NvdNode>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdNode {
    #[serde(default)]
    cpe_match: Vec<CpeMatch>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CpeMatch {
    #[serde(default)]
    vulnerable: bool,
    criteria: String,
    version_start_including: Option<String>,
    version_start_excluding: Option<String>,
    version_end_including: Option<String>,
    version_end_excluding: Option<String>,
}

pub(crate) fn parse_nvd(body: &[u8]) -> Result<NvdPage, String> {
    if body.len() > MAX_BODY_BYTES {
        return Err(format!("NVD response too large: {} bytes", body.len()));
    }
    let resp: NvdResponse = serde_json::from_slice(body)
        .map_err(|e| format!("NVD response is not valid JSON: {e}"))?;
    let mut cves = Vec::new();
    let mut seen = BTreeSet::new();
    let mut skipped = 0;
    for item in resp.vulnerabilities {
        match stage_nvd_item(item) {
            Some(c) if seen.insert(c.cve_id.clone()) => cves.push(c),
            _ => skipped += 1,
        }
    }
    Ok(NvdPage {
        total_results: resp.total_results,
        start_index: resp.start_index,
        results_per_page: resp.results_per_page,
        cves,
        skipped,
    })
}

fn stage_nvd_item(item: serde_json::Value) -> Option<FeedCve> {
    let cve: NvdCve = serde_json::from_value(item.get("cve")?.clone()).ok()?;
    let cve_id = stage_text(&cve.id, 32);
    if !is_cve_id(&cve_id) {
        return None;
    }
    let ranges = routeros_ranges(&cve.configurations);
    if ranges.is_empty() {
        return None;
    }
    let description = cve
        .descriptions
        .iter()
        .find(|d| d.lang == "en")
        .map(|d| stage_text(&d.value, MAX_DESCRIPTION))
        .unwrap_or_default();
    let metric = cve.metrics.v40.first().or(cve.metrics.v31.first());
    let (cvss_version, cvss_score, cvss_vector) = match metric {
        Some(m) if (0.0..=10.0).contains(&m.cvss_data.base_score) => (
            Some(stage_text(&m.cvss_data.version, 8)),
            Some(m.cvss_data.base_score),
            Some(stage_text(&m.cvss_data.vector_string, 256)),
        ),
        _ => (None, None, None),
    };
    let cwe = cve
        .weaknesses
        .iter()
        .flat_map(|w| &w.description)
        .find(|d| d.lang == "en")
        .map(|d| stage_text(&d.value, 64));
    Some(FeedCve {
        cve_id,
        published: stage_text(&cve.published, 40),
        last_modified: stage_text(&cve.last_modified, 40),
        description,
        cvss_version,
        cvss_score,
        cvss_vector,
        cwe,
        nvd_status: stage_text(&cve.vuln_status, 40),
        ranges_json: serde_json::to_string(&ranges).ok()?,
    })
}

/// Vulnerable RouterOS matches only, deduplicated, capped at [`MAX_RANGES`].
/// A CPE version of `-` ("not applicable") with no bounds is skipped: turning
/// it into a boundless range would claim every version is affected.
fn routeros_ranges(configs: &[NvdConfiguration]) -> Vec<VersionRange> {
    let mut out: Vec<VersionRange> = Vec::new();
    for m in configs.iter().flat_map(|c| &c.nodes).flat_map(|n| &n.cpe_match) {
        if !m.vulnerable || !m.criteria.starts_with(ROUTEROS_CPE_PREFIX) {
            continue;
        }
        let has_bounds = m.version_start_including.is_some()
            || m.version_start_excluding.is_some()
            || m.version_end_including.is_some()
            || m.version_end_excluding.is_some();
        let version_field = m.criteria.split(':').nth(5).unwrap_or("*");
        if version_field == "-" && !has_bounds {
            continue;
        }
        let bound = |b: &Option<String>| {
            b.as_deref()
                .map(|s| stage_text(s, MAX_VERSION))
                .filter(|s| !s.is_empty())
        };
        let exact = match version_field {
            "*" | "" => None,
            v if !has_bounds => Some(stage_text(v, MAX_VERSION)),
            _ => None,
        };
        let range = VersionRange {
            start_including: bound(&m.version_start_including),
            start_excluding: bound(&m.version_start_excluding),
            end_including: bound(&m.version_end_including),
            end_excluding: bound(&m.version_end_excluding),
            exact,
        };
        if !out.contains(&range) {
            out.push(range);
        }
        if out.len() >= MAX_RANGES {
            break;
        }
    }
    out
}

#[derive(Deserialize)]
struct KevResponse {
    #[serde(default)]
    vulnerabilities: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KevItem {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(default)]
    vendor_project: String,
    #[serde(default)]
    date_added: String,
    #[serde(default)]
    due_date: Option<String>,
}

/// MikroTik entries from the full KEV catalog.
pub(crate) fn parse_kev(body: &[u8]) -> Result<Vec<FeedKev>, String> {
    if body.len() > MAX_BODY_BYTES {
        return Err(format!("KEV response too large: {} bytes", body.len()));
    }
    let resp: KevResponse = serde_json::from_slice(body)
        .map_err(|e| format!("KEV response is not valid JSON: {e}"))?;
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for v in resp.vulnerabilities {
        let Ok(item) = serde_json::from_value::<KevItem>(v) else {
            continue;
        };
        if !item.vendor_project.to_ascii_lowercase().contains("mikrotik") {
            continue;
        }
        let cve_id = stage_text(&item.cve_id, 32);
        if !is_cve_id(&cve_id) || !seen.insert(cve_id.clone()) {
            continue;
        }
        out.push(FeedKev {
            cve_id,
            date_added: stage_text(&item.date_added, 40),
            due_date: item
                .due_date
                .map(|d| stage_text(&d, 40))
                .filter(|d| !d.is_empty()),
        });
    }
    Ok(out)
}

/// `CVE-YYYY-NNNN…` — four-digit year, four or more digit sequence.
pub(crate) fn is_cve_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, seq)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && (4..=19).contains(&seq.len())
        && seq.bytes().all(|b| b.is_ascii_digit())
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ion-drift-web advisory::feed`
Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ion-drift-web/src/advisory/feed.rs crates/ion-drift-web/src/advisory/mod.rs
git commit -m "feat(advisory): stage NVD and CISA KEV feed records"
```

---

### Task 4: Consent state + consent-gated fetch task

**Files:**
- Create: `crates/ion-drift-web/src/advisory/consent.rs`
- Create: `crates/ion-drift-web/src/tasks/advisory_feed.rs`
- Modify: `crates/ion-drift-web/src/advisory/mod.rs`, `crates/ion-drift-web/src/tasks/mod.rs` (mod list line 1-11; spawn after line 207)

**Interfaces:**
- Consumes: `SwitchStore::get_setting(&self, key: &str) -> Result<Option<String>, rusqlite::Error>`, `SwitchStore::set_setting(&self, key: &str, value: &str) -> Result<(), rusqlite::Error>`; `AdvisoryStore::{replace_feed_cves, replace_feed_kev, record_feed_attempt}` (Task 2); `feed::{parse_nvd, parse_kev, MAX_BODY_BYTES}` (Task 3); `crate::advisory::exploitation::now_unix() -> i64`.
- Produces: `pub(crate) enum FeedConsent { Unanswered, On, Off }` (serde snake_case); `pub(crate) struct ConsentRecord { pub consent: FeedConsent, pub set_by: Option<String>, pub set_at: Option<i64> }`; `consent::load(&SwitchStore) -> Result<ConsentRecord, String>`; `consent::save(&SwitchStore, FeedConsent, by: &str, now: i64) -> Result<(), String>`; in `tasks/advisory_feed.rs`: `pub(crate) const NVD_URL`, `KEV_URL`, `ROUTEROS_CPE`; `pub(crate) trait FeedTransport`; `pub(crate) async fn run_feed_cycle<T: FeedTransport>(consent: FeedConsent, transport: &T, store: &AdvisoryStore, now: i64, page_gap: Duration) -> FeedCycleReport`; `pub fn spawn_advisory_feed(&TaskSupervisor, AppState)`.

- [ ] **Step 1: Write the failing consent tests**

In `advisory/mod.rs` add `pub mod consent;`. Create `crates/ion-drift-web/src/advisory/consent.rs`:
```rust
//! Operator consent for the outbound vulnerability feed.

#[cfg(test)]
mod tests {
    use super::*;
    use ion_drift_storage::SwitchStore;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn fresh_install_is_unanswered() {
        let f = NamedTempFile::new().unwrap();
        let store = SwitchStore::new(f.path()).unwrap();
        let rec = load(&store).await.unwrap();
        assert_eq!(rec, ConsentRecord { consent: FeedConsent::Unanswered, set_by: None, set_at: None });
    }

    #[tokio::test]
    async fn saved_answer_persists_with_attribution_across_reopen() {
        let f = NamedTempFile::new().unwrap();
        {
            let store = SwitchStore::new(f.path()).unwrap();
            save(&store, FeedConsent::On, "scott", 1_758_700_000).await.unwrap();
        }
        let store = SwitchStore::new(f.path()).unwrap();
        let rec = load(&store).await.unwrap();
        assert_eq!(rec.consent, FeedConsent::On);
        assert_eq!(rec.set_by.as_deref(), Some("scott"));
        assert_eq!(rec.set_at, Some(1_758_700_000));
    }

    #[tokio::test]
    async fn unanswered_is_not_an_answer() {
        let f = NamedTempFile::new().unwrap();
        let store = SwitchStore::new(f.path()).unwrap();
        assert!(save(&store, FeedConsent::Unanswered, "scott", 1).await.is_err());
    }

    #[tokio::test]
    async fn corrupt_value_fails_closed() {
        let f = NamedTempFile::new().unwrap();
        let store = SwitchStore::new(f.path()).unwrap();
        store.set_setting(CONSENT_KEY, "maybe").await.unwrap();
        assert_eq!(load(&store).await.unwrap().consent, FeedConsent::Unanswered);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p ion-drift-web advisory::consent`
Expected: compile FAIL — `cannot find function load`, `ConsentRecord`, `FeedConsent`, `CONSENT_KEY`.

- [ ] **Step 3: Implement consent**

Insert above the tests in `consent.rs`:
```rust
//!
//! The feed is on by default, but "default" means preselected: nothing is
//! fetched until an administrator has answered. A missing or unrecognised
//! value reads as [`FeedConsent::Unanswered`], so a corrupt setting fails
//! closed — no outbound traffic — rather than open.

use ion_drift_storage::SwitchStore;
use serde::{Deserialize, Serialize};

pub(crate) const CONSENT_KEY: &str = "advisory_feed_consent";
pub(crate) const CONSENT_BY_KEY: &str = "advisory_feed_consent_by";
pub(crate) const CONSENT_AT_KEY: &str = "advisory_feed_consent_at";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FeedConsent {
    Unanswered,
    On,
    Off,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ConsentRecord {
    pub consent: FeedConsent,
    pub set_by: Option<String>,
    pub set_at: Option<i64>,
}

pub(crate) async fn load(store: &SwitchStore) -> Result<ConsentRecord, String> {
    let raw = store
        .get_setting(CONSENT_KEY)
        .await
        .map_err(|e| format!("read feed consent: {e}"))?;
    let consent = match raw.as_deref() {
        Some("on") => FeedConsent::On,
        Some("off") => FeedConsent::Off,
        _ => FeedConsent::Unanswered,
    };
    if consent == FeedConsent::Unanswered {
        return Ok(ConsentRecord { consent, set_by: None, set_at: None });
    }
    let set_by = store
        .get_setting(CONSENT_BY_KEY)
        .await
        .map_err(|e| format!("read feed consent author: {e}"))?;
    let set_at = store
        .get_setting(CONSENT_AT_KEY)
        .await
        .map_err(|e| format!("read feed consent time: {e}"))?
        .and_then(|s| s.parse().ok());
    Ok(ConsentRecord { consent, set_by, set_at })
}

/// Record an administrator's answer. `Unanswered` is not an answer.
///
/// Attribution is written before the decision, so an interrupted save leaves
/// the previous decision in force rather than a decision with no author.
pub(crate) async fn save(
    store: &SwitchStore,
    choice: FeedConsent,
    by: &str,
    now: i64,
) -> Result<(), String> {
    let value = match choice {
        FeedConsent::On => "on",
        FeedConsent::Off => "off",
        FeedConsent::Unanswered => return Err("feed consent must be on or off".to_string()),
    };
    store
        .set_setting(CONSENT_BY_KEY, by)
        .await
        .map_err(|e| format!("write feed consent author: {e}"))?;
    store
        .set_setting(CONSENT_AT_KEY, &now.to_string())
        .await
        .map_err(|e| format!("write feed consent time: {e}"))?;
    store
        .set_setting(CONSENT_KEY, value)
        .await
        .map_err(|e| format!("write feed consent: {e}"))?;
    Ok(())
}
```
Run: `cargo test -p ion-drift-web advisory::consent` → 4 passed.

- [ ] **Step 4: Write the failing fetch-cycle tests**

In `tasks/mod.rs` add `mod advisory_feed;` after `mod advisory;`. Create `crates/ion-drift-web/src/tasks/advisory_feed.rs`:
```rust
//! Vulnerability feed — daily NVD + CISA KEV pull for RouterOS.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::feed::fixtures;
    use std::sync::Mutex;
    use tempfile::NamedTempFile;

    struct MockTransport {
        calls: Mutex<Vec<String>>,
        nvd: Result<Vec<u8>, String>,
        kev: Result<Vec<u8>, String>,
    }

    impl MockTransport {
        fn new(nvd: Result<Vec<u8>, String>, kev: Result<Vec<u8>, String>) -> Self {
            Self { calls: Mutex::new(Vec::new()), nvd, kev }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl FeedTransport for MockTransport {
        async fn get(&self, url: &str) -> Result<Vec<u8>, String> {
            self.calls.lock().unwrap().push(url.to_string());
            if url.starts_with(NVD_URL) {
                self.nvd.clone()
            } else if url == KEV_URL {
                self.kev.clone()
            } else {
                Err(format!("unexpected url {url}"))
            }
        }
    }

    async fn store() -> (NamedTempFile, AdvisoryStore) {
        let f = NamedTempFile::new().unwrap();
        let s = AdvisoryStore::new(f.path()).await.unwrap();
        (f, s)
    }

    const NO_GAP: Duration = Duration::ZERO;

    #[tokio::test]
    async fn no_request_is_made_until_consent_is_on() {
        let (_f, store) = store().await;
        let t = MockTransport::new(Ok(fixtures::nvd_body()), Ok(fixtures::kev_body()));
        for consent in [FeedConsent::Unanswered, FeedConsent::Off] {
            let report = run_feed_cycle(consent, &t, &store, 1, NO_GAP).await;
            assert!(report.skipped_for_consent);
        }
        assert!(t.calls().is_empty(), "no outbound request before consent");
        assert!(store.feed_states().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn consent_on_stores_nvd_and_kev() {
        let (_f, store) = store().await;
        let t = MockTransport::new(Ok(fixtures::nvd_body()), Ok(fixtures::kev_body()));
        let report = run_feed_cycle(FeedConsent::On, &t, &store, 100, NO_GAP).await;
        assert_eq!(report.nvd, Some(Ok(1)));
        assert_eq!(report.kev, Some(Ok(1)));
        assert_eq!(store.list_feed_cves().await.unwrap()[0].cve_id, "CVE-2026-86060");
        assert_eq!(store.list_feed_kev().await.unwrap()[0].cve_id, "CVE-2026-86060");
    }

    #[tokio::test]
    async fn only_the_two_constant_hosts_are_contacted() {
        let (_f, store) = store().await;
        let t = MockTransport::new(Ok(fixtures::nvd_body()), Ok(fixtures::kev_body()));
        run_feed_cycle(FeedConsent::On, &t, &store, 100, NO_GAP).await;
        for url in t.calls() {
            assert!(url.starts_with(NVD_URL) || url == KEV_URL, "unexpected host: {url}");
        }
    }

    #[tokio::test]
    async fn failed_fetch_keeps_last_known_good() {
        let (_f, store) = store().await;
        let good = MockTransport::new(Ok(fixtures::nvd_body()), Ok(fixtures::kev_body()));
        run_feed_cycle(FeedConsent::On, &good, &store, 100, NO_GAP).await;

        let bad = MockTransport::new(Err("HTTP 503".into()), Err("timeout".into()));
        let report = run_feed_cycle(FeedConsent::On, &bad, &store, 200, NO_GAP).await;
        assert!(matches!(report.nvd, Some(Err(_))));

        assert_eq!(store.list_feed_cves().await.unwrap().len(), 1);
        assert_eq!(store.list_feed_kev().await.unwrap().len(), 1);
        let nvd = store.feed_states().await.unwrap().into_iter().find(|s| s.source == "nvd").unwrap();
        assert_eq!(nvd.last_success_at, Some(100));
        assert_eq!(nvd.last_attempt_at, 200);
        assert_eq!(nvd.last_error.as_deref(), Some("HTTP 503"));
    }

    #[tokio::test]
    async fn nvd_failure_does_not_block_kev() {
        let (_f, store) = store().await;
        let t = MockTransport::new(Err("HTTP 503".into()), Ok(fixtures::kev_body()));
        let report = run_feed_cycle(FeedConsent::On, &t, &store, 100, NO_GAP).await;
        assert!(matches!(report.nvd, Some(Err(_))));
        assert_eq!(report.kev, Some(Ok(1)));
    }

    #[test]
    fn next_delay_follows_the_outcome() {
        let skipped = FeedCycleReport { skipped_for_consent: true, ..Default::default() };
        assert_eq!(next_delay(&skipped, 0), Duration::from_secs(CONSENT_RECHECK_SECS));
        let failed = FeedCycleReport { nvd: Some(Err("x".into())), kev: Some(Ok(1)), ..Default::default() };
        assert_eq!(next_delay(&failed, 0), Duration::from_secs(RETRY_SECS));
        let ok = FeedCycleReport { nvd: Some(Ok(1)), kev: Some(Ok(1)), ..Default::default() };
        assert_eq!(next_delay(&ok, 0), Duration::from_secs(REFRESH_SECS));
        assert_eq!(next_delay(&ok, 1_799), Duration::from_secs(REFRESH_SECS + 1_799));
    }
}
```

- [ ] **Step 5: Run to verify failure**

Run: `cargo test -p ion-drift-web tasks::advisory_feed`
Expected: compile FAIL — `cannot find trait FeedTransport`, `run_feed_cycle`, `FeedCycleReport`, `next_delay`.

- [ ] **Step 6: Implement the fetch cycle and task**

Insert above the tests in `tasks/advisory_feed.rs`:
```rust
//!
//! Outbound traffic is gated on operator consent: while the answer is anything
//! but `on`, this task makes no request at all. Hosts are compile-time
//! constants — never configuration — and redirects are only followed within
//! the same host, so no operator-, catalog-, or module-influenced destination
//! is ever contacted.

use std::time::Duration;

use ion_drift_storage::{AdvisoryStore, FeedCve};

use crate::advisory::consent::{self, FeedConsent};
use crate::advisory::exploitation::now_unix;
use crate::advisory::feed;
use crate::state::AppState;
use crate::task_supervisor::TaskSupervisor;

pub(crate) const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
pub(crate) const ROUTEROS_CPE: &str = "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*";
pub(crate) const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const STARTUP_DELAY_SECS: u64 = 240;
const REFRESH_SECS: u64 = 86_400;
/// While consent is not `on`, re-read it this often, so a "Keep on" answer
/// starts the feed within minutes.
const CONSENT_RECHECK_SECS: u64 = 300;
const RETRY_SECS: u64 = 3_600;
const JITTER_SECS: u64 = 1_800;
const PAGE_SIZE: u64 = 2_000;
const MAX_PAGES: u64 = 10;
/// NVD's unauthenticated limit is 5 requests per rolling 30 s.
const PAGE_GAP: Duration = Duration::from_secs(7);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) trait FeedTransport {
    async fn get(&self, url: &str) -> Result<Vec<u8>, String>;
}

pub(crate) struct ReqwestTransport {
    client: reqwest::Client,
}

impl FeedTransport for ReqwestTransport {
    async fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        let mut resp = self
            .client
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .header(
                reqwest::header::USER_AGENT,
                concat!("ion-drift/", env!("CARGO_PKG_VERSION")),
            )
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| format!("read failed: {e}"))? {
            if body.len() + chunk.len() > feed::MAX_BODY_BYTES {
                return Err("response exceeded size cap".to_string());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

fn build_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let same_host = attempt.previous().first().and_then(|u| u.host_str())
                == attempt.url().host_str();
            if same_host && attempt.previous().len() < 3 {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .build()
        .map_err(|e| format!("build feed http client: {e}"))
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct FeedCycleReport {
    pub skipped_for_consent: bool,
    pub nvd: Option<Result<usize, String>>,
    pub kev: Option<Result<usize, String>>,
}

/// One feed cycle. With consent anything but `On`, returns without a request.
/// NVD and KEV are independent: one failing never blocks the other, and a
/// failure never replaces stored data.
pub(crate) async fn run_feed_cycle<T: FeedTransport>(
    consent: FeedConsent,
    transport: &T,
    store: &AdvisoryStore,
    now: i64,
    page_gap: Duration,
) -> FeedCycleReport {
    if consent != FeedConsent::On {
        return FeedCycleReport { skipped_for_consent: true, ..Default::default() };
    }

    let nvd = match fetch_nvd(transport, page_gap).await {
        Ok(cves) => store.replace_feed_cves(&cves, now).await,
        Err(e) => Err(e),
    };
    record(store, "nvd", now, &nvd).await;

    let kev = match transport.get(KEV_URL).await.and_then(|b| feed::parse_kev(&b)) {
        Ok(entries) => store.replace_feed_kev(&entries, now).await,
        Err(e) => Err(e),
    };
    record(store, "kev", now, &kev).await;

    FeedCycleReport { skipped_for_consent: false, nvd: Some(nvd), kev: Some(kev) }
}

async fn record(store: &AdvisoryStore, source: &str, now: i64, outcome: &Result<usize, String>) {
    let outcome = outcome.as_ref().map(|n| *n as i64).map_err(String::as_str);
    if let Err(e) = store.record_feed_attempt(source, now, outcome).await {
        tracing::warn!(source, error = %e, "advisory feed: could not record attempt");
    }
}

async fn fetch_nvd<T: FeedTransport>(transport: &T, page_gap: Duration) -> Result<Vec<FeedCve>, String> {
    let mut all: Vec<FeedCve> = Vec::new();
    let mut start = 0u64;
    for page_no in 0..MAX_PAGES {
        if page_no > 0 {
            tokio::time::sleep(page_gap).await;
        }
        let url = format!(
            "{NVD_URL}?virtualMatchString={ROUTEROS_CPE}&resultsPerPage={PAGE_SIZE}&startIndex={start}"
        );
        let page = feed::parse_nvd(&transport.get(&url).await?)?;
        if page.skipped > 0 {
            tracing::debug!(skipped = page.skipped, "advisory feed: NVD records skipped");
        }
        all.extend(page.cves);
        start = page.start_index + page.results_per_page.max(1);
        if start >= page.total_results {
            all.sort_by(|a, b| a.cve_id.cmp(&b.cve_id));
            all.dedup_by(|a, b| a.cve_id == b.cve_id);
            return Ok(all);
        }
    }
    Err(format!("NVD pagination exceeded {MAX_PAGES} pages"))
}

/// `jitter` is 0..JITTER_SECS; passed in so the schedule is testable.
fn next_delay(report: &FeedCycleReport, jitter: u64) -> Duration {
    if report.skipped_for_consent {
        return Duration::from_secs(CONSENT_RECHECK_SECS);
    }
    let failed = matches!(report.nvd, Some(Err(_))) || matches!(report.kev, Some(Err(_)));
    if failed {
        Duration::from_secs(RETRY_SECS)
    } else {
        Duration::from_secs(REFRESH_SECS + jitter)
    }
}

fn jitter() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    nanos % JITTER_SECS
}

/// Spawn the supervised feed loop.
pub fn spawn_advisory_feed(supervisor: &TaskSupervisor, state: AppState) {
    supervisor.spawn("advisory-feed", move || {
        let state = state.clone();
        Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(STARTUP_DELAY_SECS)).await;
            tracing::info!("advisory feed starting");
            loop {
                let consent = match consent::load(&state.switch_store).await {
                    Ok(r) => r.consent,
                    Err(e) => {
                        tracing::warn!(error = %e, "advisory feed: consent unreadable; treating as unanswered");
                        FeedConsent::Unanswered
                    }
                };
                let report = match build_client() {
                    Ok(client) => {
                        run_feed_cycle(consent, &ReqwestTransport { client }, &state.advisory_store, now_unix(), PAGE_GAP).await
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "advisory feed: http client unavailable");
                        FeedCycleReport { nvd: Some(Err(e.clone())), kev: Some(Err(e)), ..Default::default() }
                    }
                };
                if !report.skipped_for_consent {
                    tracing::info!(nvd = ?report.nvd, kev = ?report.kev, "advisory feed cycle complete");
                }
                tokio::time::sleep(next_delay(&report, jitter())).await;
            }
        })
    });
}
```

In `tasks/mod.rs`, after the `advisory::spawn_advisory_evaluator(...)` call (line ~207), add:
```rust
    // Vulnerability feed (NVD + CISA KEV) — idle until an admin consents
    advisory_feed::spawn_advisory_feed(&state.task_supervisor, state.clone());
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p ion-drift-web tasks::advisory_feed advisory::consent`
Expected: 10 passed.

- [ ] **Step 8: Commit**

```bash
git add crates/ion-drift-web/src/advisory/consent.rs crates/ion-drift-web/src/advisory/mod.rs \
        crates/ion-drift-web/src/tasks/advisory_feed.rs crates/ion-drift-web/src/tasks/mod.rs
git commit -m "feat(advisory): consent-gated daily NVD and KEV feed task"
```

---

### Task 5: Feed status + consent API

**Files:**
- Create: `crates/ion-drift-web/src/routes/advisory_feed.rs`
- Modify: `crates/ion-drift-web/src/routes/mod.rs` (`pub mod` list near line 8; route list near lines 468-472)

**Interfaces:**
- Consumes: `consent::{load, save, ConsentRecord, FeedConsent}` (Task 4); `AdvisoryStore::feed_states` (Task 2); `RequireAuth(SessionData)`, `RequireAdmin(SessionData)` from `crate::middleware`; `super::internal_error(context: &str, e: impl Display) -> Response`.
- Produces: `GET /api/advisory/feed` → `FeedStatusResponse { consent, set_by, set_at, sources: Vec<FeedSourceState>, stale: bool }` (consent fields flattened); `POST /api/advisory/feed/consent` body `{"consent":"on"|"off"}` → same response; `pub(crate) fn is_stale(FeedConsent, &[FeedSourceState], now: i64) -> bool`.

- [ ] **Step 1: Write the failing tests**

Create `crates/ion-drift-web/src/routes/advisory_feed.rs`:
```rust
//! Vulnerability feed status and consent.

#[cfg(test)]
mod tests {
    use super::*;
    use ion_drift_storage::FeedSourceState;

    const DAY: i64 = 86_400;

    fn src(source: &str, last_success_at: Option<i64>, last_attempt_at: i64) -> FeedSourceState {
        FeedSourceState { source: source.into(), last_success_at, last_attempt_at, last_error: None, records: 1 }
    }

    #[test]
    fn fresh_sources_are_not_stale() {
        let now = 10 * DAY;
        let s = [src("kev", Some(now - DAY), now - DAY), src("nvd", Some(now - DAY), now - DAY)];
        assert!(!is_stale(FeedConsent::On, &s, now));
    }

    #[test]
    fn source_without_success_for_three_days_is_stale() {
        let now = 10 * DAY;
        let s = [src("kev", Some(now - DAY), now), src("nvd", Some(now - 4 * DAY), now)];
        assert!(is_stale(FeedConsent::On, &s, now));
    }

    #[test]
    fn source_that_never_succeeded_is_stale() {
        assert!(is_stale(FeedConsent::On, &[src("nvd", None, 5)], 10));
    }

    #[test]
    fn no_attempt_yet_is_pending_not_stale() {
        assert!(!is_stale(FeedConsent::On, &[], 10));
    }

    #[test]
    fn staleness_only_applies_when_consent_is_on() {
        let s = [src("nvd", None, 5)];
        assert!(!is_stale(FeedConsent::Off, &s, 10 * DAY));
        assert!(!is_stale(FeedConsent::Unanswered, &s, 10 * DAY));
    }

    #[test]
    fn consent_body_accepts_only_known_values() {
        assert!(serde_json::from_str::<ConsentBody>(r#"{"consent":"on"}"#).is_ok());
        assert!(serde_json::from_str::<ConsentBody>(r#"{"consent":"maybe"}"#).is_err());
        assert!(serde_json::from_str::<ConsentBody>(r#"{"consent":"on","extra":1}"#).is_err());
    }
}
```
In `routes/mod.rs` add `pub mod advisory_feed;` to the `pub mod` list.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p ion-drift-web routes::advisory_feed`
Expected: compile FAIL — `cannot find function is_stale`, `ConsentBody`.

- [ ] **Step 3: Implement**

Insert above the tests in `routes/advisory_feed.rs`:
```rust
//!
//! Anyone signed in may read the status (the Findings page needs it); only an
//! administrator may answer the consent question. `unanswered` is rejected as
//! an answer so the only way out of the dialog is an explicit on or off.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use ion_drift_storage::FeedSourceState;
use serde::{Deserialize, Serialize};

use super::internal_error;
use crate::advisory::consent::{self, ConsentRecord, FeedConsent};
use crate::advisory::exploitation::now_unix;
use crate::middleware::{RequireAdmin, RequireAuth};
use crate::state::AppState;

/// A source is stale once it has been tried and has not succeeded for this long.
pub(crate) const STALE_AFTER_SECS: i64 = 3 * 86_400;

#[derive(Serialize)]
pub struct FeedStatusResponse {
    #[serde(flatten)]
    consent: ConsentRecord,
    sources: Vec<FeedSourceState>,
    stale: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentBody {
    consent: FeedConsent,
}

pub(crate) fn is_stale(consent: FeedConsent, sources: &[FeedSourceState], now: i64) -> bool {
    consent == FeedConsent::On
        && sources
            .iter()
            .any(|s| s.last_success_at.is_none_or(|t| now - t > STALE_AFTER_SECS))
}

async fn build_status(state: &AppState) -> Result<FeedStatusResponse, Response> {
    let consent = consent::load(&state.switch_store)
        .await
        .map_err(|e| internal_error("load feed consent", e))?;
    let sources = state
        .advisory_store
        .feed_states()
        .await
        .map_err(|e| internal_error("load feed state", e))?;
    let stale = is_stale(consent.consent, &sources, now_unix());
    Ok(FeedStatusResponse { consent, sources, stale })
}

// ── GET /api/advisory/feed ──────────────────────────────────────

pub async fn feed_status(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<FeedStatusResponse>, Response> {
    build_status(&state).await.map(Json)
}

// ── POST /api/advisory/feed/consent ─────────────────────────────

pub async fn set_feed_consent(
    RequireAdmin(session): RequireAdmin,
    State(state): State<AppState>,
    Json(body): Json<ConsentBody>,
) -> Result<Json<FeedStatusResponse>, Response> {
    if body.consent == FeedConsent::Unanswered {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "consent must be \"on\" or \"off\"" })),
        )
            .into_response());
    }
    consent::save(&state.switch_store, body.consent, &session.username, now_unix())
        .await
        .map_err(|e| internal_error("save feed consent", e))?;
    tracing::info!(consent = ?body.consent, by = %session.username, "advisory feed consent recorded");
    build_status(&state).await.map(Json)
}
```

In `routes/mod.rs`, add next to the `/findings` routes (each on ONE line):
```rust
        .route("/advisory/feed", get(advisory_feed::feed_status))
        .route("/advisory/feed/consent", post(advisory_feed::set_feed_consent))
```

- [ ] **Step 4: Run the tests, including the authz regression test**

Run: `cargo test -p ion-drift-web routes::advisory_feed && cargo test -p ion-drift-web --test authz_test`
Expected: 6 passed; `authz_test` passes (the new POST is admin-guarded by the `RequireAdmin` extractor).

- [ ] **Step 5: Commit**

```bash
git add crates/ion-drift-web/src/routes/advisory_feed.rs crates/ion-drift-web/src/routes/mod.rs
git commit -m "feat(api): advisory feed status and admin consent endpoints"
```

---

### Task 6: Consent dialog, non-admin banner, Settings card

**Files:**
- Create: `web/src/api/queries/advisory.ts`, `web/src/components/advisory-feed-consent.tsx`, `web/src/features/settings/settings-advisory-feed.tsx`, `web/src/components/__tests__/advisory-feed-consent.test.tsx`
- Modify: `web/src/api/queries/index.ts`, `web/src/routes/__root.tsx`, `web/src/features/settings/settings-security.tsx`

**Interfaces:**
- Consumes: `GET /api/advisory/feed`, `POST /api/advisory/feed/consent` (Task 5); `useAuth()` → `{ user: { is_admin: boolean } | null }`; `apiFetch<T>(path, init)`; test utils `mockFetchRoutes(routes)` (keys `"METHOD /path"`) and `renderWithClient(ui)`.
- Produces: `useAdvisoryFeedStatus()`, `useSetAdvisoryFeedConsent()`, types `FeedConsent`, `AdvisoryFeedStatus`, `FeedSourceState`; components `AdvisoryFeedConsentGate`, `SettingsAdvisoryFeed`; const `FEED_HOSTS`.

- [ ] **Step 1: Write the failing tests**

Create `web/src/components/__tests__/advisory-feed-consent.test.tsx`:
```tsx
// Vulnerability feed consent: the dialog blocks admins until answered, cannot
// be dismissed, and "off" requires a second, warned confirmation.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { AdvisoryFeedConsentGate } from "../advisory-feed-consent";
import { SettingsAdvisoryFeed } from "@/features/settings/settings-advisory-feed";
import { mockFetchRoutes, renderWithClient } from "@/test/utils";
import type { AdvisoryFeedStatus, FeedConsent } from "@/api/queries/advisory";

const admin = { authenticated: true, user: { user_id: "1", username: "scott", email: null, is_admin: true } };
const viewer = { authenticated: true, user: { user_id: "2", username: "viewer", email: null, is_admin: false } };

function status(consent: FeedConsent): AdvisoryFeedStatus {
  return { consent, set_by: consent === "unanswered" ? null : "scott", set_at: consent === "unanswered" ? null : 1_758_700_000, sources: [], stale: false };
}

function consentPosts(calls: ReturnType<typeof mockFetchRoutes>) {
  return calls.filter((c) => c.method === "POST" && c.url.endsWith("/api/advisory/feed/consent"));
}

describe("AdvisoryFeedConsentGate", () => {
  it("blocks admins and cannot be dismissed", async () => {
    mockFetchRoutes({ "GET /auth/status": admin, "GET /api/advisory/feed": status("unanswered") });
    renderWithClient(<AdvisoryFeedConsentGate />);
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("services.nvd.nist.gov");
    expect(dialog).toHaveTextContent("www.cisa.gov");
    expect(screen.queryByRole("button", { name: /close|dismiss|cancel/i })).toBeNull();
    await userEvent.keyboard("{Escape}");
    await userEvent.click(screen.getByTestId("feed-consent-backdrop"));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("keep on records consent on", async () => {
    const calls = mockFetchRoutes({
      "GET /auth/status": admin,
      "GET /api/advisory/feed": status("unanswered"),
      "POST /api/advisory/feed/consent": status("on"),
    });
    renderWithClient(<AdvisoryFeedConsentGate />);
    await userEvent.click(await screen.findByRole("button", { name: /keep on/i }));
    await waitFor(() => expect(consentPosts(calls).map((c) => c.body)).toEqual([{ consent: "on" }]));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("turn off requires a warned second confirmation", async () => {
    const calls = mockFetchRoutes({
      "GET /auth/status": admin,
      "GET /api/advisory/feed": status("unanswered"),
      "POST /api/advisory/feed/consent": status("off"),
    });
    renderWithClient(<AdvisoryFeedConsentGate />);
    await userEvent.click(await screen.findByRole("button", { name: /^turn off$/i }));
    expect(screen.getByRole("dialog")).toHaveTextContent(/will not learn about new vulnerabilities/i);
    expect(consentPosts(calls)).toHaveLength(0);
    await userEvent.click(screen.getByRole("button", { name: /back/i }));
    expect(screen.getByRole("button", { name: /keep on/i })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^turn off$/i }));
    await userEvent.click(screen.getByRole("button", { name: /turn off anyway/i }));
    await waitFor(() => expect(consentPosts(calls).map((c) => c.body)).toEqual([{ consent: "off" }]));
  });

  it("non-admins see a banner instead of the dialog", async () => {
    mockFetchRoutes({ "GET /auth/status": viewer, "GET /api/advisory/feed": status("unanswered") });
    renderWithClient(<AdvisoryFeedConsentGate />);
    expect(await screen.findByRole("status")).toHaveTextContent(/awaiting administrator confirmation/i);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("renders nothing once answered", async () => {
    mockFetchRoutes({ "GET /auth/status": admin, "GET /api/advisory/feed": status("on") });
    const { container } = renderWithClient(<AdvisoryFeedConsentGate />);
    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });
});

describe("SettingsAdvisoryFeed", () => {
  it("turning off from settings warns before saving", async () => {
    const calls = mockFetchRoutes({
      "GET /auth/status": admin,
      "GET /api/advisory/feed": status("on"),
      "POST /api/advisory/feed/consent": status("off"),
    });
    renderWithClient(<SettingsAdvisoryFeed />);
    expect(await screen.findByText(/set by scott/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^turn off$/i }));
    expect(screen.getByText(/will not learn about new vulnerabilities/i)).toBeInTheDocument();
    expect(consentPosts(calls)).toHaveLength(0);
    await userEvent.click(screen.getByRole("button", { name: /turn off anyway/i }));
    await waitFor(() => expect(consentPosts(calls).map((c) => c.body)).toEqual([{ consent: "off" }]));
  });

  it("turning on from settings needs no warning", async () => {
    const calls = mockFetchRoutes({
      "GET /auth/status": admin,
      "GET /api/advisory/feed": status("off"),
      "POST /api/advisory/feed/consent": status("on"),
    });
    renderWithClient(<SettingsAdvisoryFeed />);
    await userEvent.click(await screen.findByRole("button", { name: /^turn on$/i }));
    await waitFor(() => expect(consentPosts(calls).map((c) => c.body)).toEqual([{ consent: "on" }]));
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd web && npx vitest run src/components/__tests__/advisory-feed-consent.test.tsx`
Expected: FAIL — cannot resolve `../advisory-feed-consent`.

- [ ] **Step 3: Implement the query hooks**

Create `web/src/api/queries/advisory.ts`:
```ts
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "../client";

// Mirrors crates/ion-drift-web/src/routes/advisory_feed.rs::FeedStatusResponse

export type FeedConsent = "unanswered" | "on" | "off";

export interface FeedSourceState {
  source: "nvd" | "kev";
  last_success_at: number | null;
  last_attempt_at: number;
  last_error: string | null;
  records: number;
}

export interface AdvisoryFeedStatus {
  consent: FeedConsent;
  set_by: string | null;
  set_at: number | null;
  sources: FeedSourceState[];
  stale: boolean;
}

const FEED_KEY = ["advisory", "feed"] as const;

export function useAdvisoryFeedStatus() {
  return useQuery({
    queryKey: FEED_KEY,
    queryFn: () => apiFetch<AdvisoryFeedStatus>("/api/advisory/feed"),
    refetchInterval: 60_000,
  });
}

export function useSetAdvisoryFeedConsent() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (consent: "on" | "off") =>
      apiFetch<AdvisoryFeedStatus>("/api/advisory/feed/consent", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ consent }),
      }),
    onSuccess: (data) => {
      queryClient.setQueryData(FEED_KEY, data);
    },
  });
}
```
Add to `web/src/api/queries/index.ts`: `export * from './advisory';`

- [ ] **Step 4: Implement the gate**

Create `web/src/components/advisory-feed-consent.tsx`:
```tsx
import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { useAuth } from "@/hooks/use-auth";
import { useAdvisoryFeedStatus, useSetAdvisoryFeedConsent } from "@/api/queries";

/** The only hosts the feed contacts. Keep in sync with tasks/advisory_feed.rs. */
export const FEED_HOSTS = ["services.nvd.nist.gov", "www.cisa.gov"] as const;

export const FEED_OFF_WARNING =
  "Ion Drift will not learn about new vulnerabilities. Only advisories bundled with this release will be checked, and newly published or actively exploited RouterOS vulnerabilities affecting your devices will not be reported.";

/**
 * Blocks administrators until they answer the vulnerability-feed question.
 * The server is the only record of the answer — there is no client-side
 * "seen" flag — so a reload or another browser shows it again until answered.
 */
export function AdvisoryFeedConsentGate() {
  const { user } = useAuth();
  const { data } = useAdvisoryFeedStatus();
  if (!data || data.consent !== "unanswered") return null;
  if (!user?.is_admin) {
    return (
      <div role="status" className="border-b border-amber-500/40 bg-amber-500/10 px-4 py-2 text-sm text-amber-200">
        Vulnerability feed awaiting administrator confirmation.
      </div>
    );
  }
  return <ConsentDialog />;
}

function ConsentDialog() {
  const [step, setStep] = useState<"choose" | "confirm-off">("choose");
  const setConsent = useSetAdvisoryFeedConsent();
  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    dialogRef.current?.focus();
  }, [step]);

  // No close button, no backdrop dismissal, no Escape: the only exits are the two answers.
  const swallowEscape = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
    }
  };

  return (
    <div data-testid="feed-consent-backdrop" className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70">
      <div
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby="feed-consent-title"
        onKeyDown={swallowEscape}
        className="mx-4 w-full max-w-lg rounded-lg border border-border bg-card p-6 shadow-xl outline-none"
      >
        {step === "choose" ? (
          <>
            <h2 id="feed-consent-title" className="text-lg font-semibold">Vulnerability feed</h2>
            <p className="mt-3 text-sm text-muted-foreground">
              Ion Drift checks your RouterOS devices against published vulnerabilities. To learn about new
              ones, it downloads public vulnerability data once a day from:
            </p>
            <ul className="mt-2 list-disc pl-5 text-sm">
              {FEED_HOSTS.map((h) => (
                <li key={h}><code>{h}</code></li>
              ))}
            </ul>
            <p className="mt-3 text-sm text-muted-foreground">
              These are plain downloads. Nothing about this installation, your network, or your devices is sent.
            </p>
            {setConsent.isError && (
              <p role="alert" className="mt-3 text-sm text-red-400">Could not save your choice. Try again.</p>
            )}
            <div className="mt-6 flex justify-end gap-3">
              <button type="button" onClick={() => setStep("confirm-off")} disabled={setConsent.isPending}
                className="rounded-md border border-border px-4 py-2 text-sm hover:bg-muted">
                Turn off
              </button>
              <button type="button" onClick={() => setConsent.mutate("on")} disabled={setConsent.isPending}
                className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90">
                Keep on (recommended)
              </button>
            </div>
          </>
        ) : (
          <>
            <h2 id="feed-consent-title" className="text-lg font-semibold">Turn off the vulnerability feed?</h2>
            <p className="mt-3 text-sm text-amber-200">{FEED_OFF_WARNING}</p>
            <p className="mt-3 text-sm text-muted-foreground">You can turn it back on at any time in Settings → Security.</p>
            {setConsent.isError && (
              <p role="alert" className="mt-3 text-sm text-red-400">Could not save your choice. Try again.</p>
            )}
            <div className="mt-6 flex justify-end gap-3">
              <button type="button" onClick={() => setStep("choose")} disabled={setConsent.isPending}
                className="rounded-md border border-border px-4 py-2 text-sm hover:bg-muted">
                Back
              </button>
              <button type="button" onClick={() => setConsent.mutate("off")} disabled={setConsent.isPending}
                className="rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-600/90">
                Turn off anyway
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
```

- [ ] **Step 5: Implement the Settings card**

Create `web/src/features/settings/settings-advisory-feed.tsx`:
```tsx
import { useState } from "react";
import { useAuth } from "@/hooks/use-auth";
import { useAdvisoryFeedStatus, useSetAdvisoryFeedConsent } from "@/api/queries";
import { FEED_HOSTS, FEED_OFF_WARNING } from "@/components/advisory-feed-consent";

function when(ts: number | null): string {
  return ts == null ? "never" : new Date(ts * 1000).toLocaleString();
}

export function SettingsAdvisoryFeed() {
  const { user } = useAuth();
  const { data } = useAdvisoryFeedStatus();
  const setConsent = useSetAdvisoryFeedConsent();
  const [confirmingOff, setConfirmingOff] = useState(false);
  if (!data) return null;

  const label = data.consent === "on" ? "On" : data.consent === "off" ? "Off" : "Awaiting confirmation";

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <h3 className="text-sm font-semibold">Vulnerability feed</h3>
      <p className="mt-1 text-sm text-muted-foreground">
        Daily download of public RouterOS vulnerability data from {FEED_HOSTS.join(" and ")}. Nothing about this
        installation is sent.
      </p>
      <p className="mt-3 text-sm">
        Status: <span className="font-medium">{label}</span>
        {data.set_by && <> — set by {data.set_by} on {when(data.set_at)}</>}
      </p>
      {data.sources.length > 0 && (
        <ul className="mt-2 space-y-1 text-xs text-muted-foreground">
          {data.sources.map((s) => (
            <li key={s.source}>
              {s.source.toUpperCase()}: last success {when(s.last_success_at)}, {s.records} records
              {s.last_error && <> — last error: {s.last_error}</>}
            </li>
          ))}
        </ul>
      )}
      {user?.is_admin && data.consent !== "unanswered" && (
        <div className="mt-4">
          {data.consent === "off" ? (
            <button type="button" onClick={() => setConsent.mutate("on")} disabled={setConsent.isPending}
              className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground">
              Turn on
            </button>
          ) : confirmingOff ? (
            <div className="space-y-3 rounded-md border border-amber-500/40 bg-amber-500/10 p-3">
              <p className="text-sm text-amber-200">{FEED_OFF_WARNING}</p>
              <div className="flex gap-2">
                <button type="button" onClick={() => setConfirmingOff(false)}
                  className="rounded-md border border-border px-3 py-1.5 text-sm">Back</button>
                <button type="button"
                  onClick={() => setConsent.mutate("off", { onSuccess: () => setConfirmingOff(false) })}
                  disabled={setConsent.isPending}
                  className="rounded-md bg-red-600 px-3 py-1.5 text-sm font-medium text-white">
                  Turn off anyway
                </button>
              </div>
            </div>
          ) : (
            <button type="button" onClick={() => setConfirmingOff(true)}
              className="rounded-md border border-border px-3 py-1.5 text-sm">
              Turn off
            </button>
          )}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 6: Mount both**

In `web/src/routes/__root.tsx`: add `import { AdvisoryFeedConsentGate } from "@/components/advisory-feed-consent";` with the other component imports, and change
```tsx
        <LicenseBanner />
```
to
```tsx
        <LicenseBanner />
        <AdvisoryFeedConsentGate />
```

In `web/src/features/settings/settings-security.tsx`: add `import { SettingsAdvisoryFeed } from "./settings-advisory-feed";` and change
```tsx
    <div className="space-y-6">
      <SecretsSection />
```
to
```tsx
    <div className="space-y-6">
      <SettingsAdvisoryFeed />
      <SecretsSection />
```

- [ ] **Step 7: Run tests and typecheck**

Run: `cd web && npx vitest run src/components/__tests__/advisory-feed-consent.test.tsx && npx tsc --noEmit && npm test`
Expected: 7 new tests pass; typecheck clean; full vitest suite green.

- [ ] **Step 8: Commit**

```bash
git add web/src/api/queries/advisory.ts web/src/api/queries/index.ts \
        web/src/components/advisory-feed-consent.tsx web/src/components/__tests__/advisory-feed-consent.test.tsx \
        web/src/features/settings/settings-advisory-feed.tsx web/src/features/settings/settings-security.tsx \
        web/src/routes/__root.tsx
git commit -m "feat(web): mandatory vulnerability-feed consent dialog and settings"
```

---

## Phase B — Version findings

### Task 7: Vulnerability findings — assess + reconcile

**Files:**
- Create: `crates/ion-drift-web/src/advisory/vulnerable.rs`
- Modify: `crates/ion-drift-web/src/advisory/mod.rs`

**Interfaces:**
- Consumes: `version::{evaluate, Applicability, VersionRange}` (Task 1); `exploitation::ADVISORY_MODULE`; `FindingsStore::{list_findings, upsert_finding, resolve_by_key, reopen_by_key}`; `FindingV1`, `FindingSeverity`, `FindingEvidence` from `ion_drift_module_api`.
- Produces: `pub(crate) const VULN_CATEGORY: &str = "advisory_vulnerable"`; `pub(crate) fn vuln_finding_id(device_id: &str, cve_id: &str) -> String` (`<device>:ver:<CVE>`); `pub(crate) enum VulnSource { Nvd, Catalog }`; `pub(crate) struct VulnInput { cve_id, title: Option<String>, description, cvss_score: Option<f64>, cvss_vector: Option<String>, ranges: Vec<VersionRange>, kev_date_added: Option<String>, mitigations: Vec<String>, source: VulnSource }`; `pub(crate) struct VulnAssessment { device_version: String, affected: Vec<FindingV1>, not_affected: BTreeSet<String>, cannot_evaluate: Vec<String> }`; `pub(crate) fn severity_for(Option<f64>, on_kev: bool) -> FindingSeverity`; `pub(crate) fn assess(device_id: &str, device_version: &str, inputs: &[VulnInput], now: i64) -> VulnAssessment`; `pub(crate) async fn reconcile(store: &FindingsStore, assessment: &VulnAssessment) -> Result<(), String>`.

- [ ] **Step 1: Write the failing tests**

Add `pub mod vulnerable;` to `advisory/mod.rs`. Create `vulnerable.rs`:
```rust
//! Version-based vulnerability findings.

#[cfg(test)]
mod tests {
    use super::*;
    use ion_drift_storage::{FindingStatus, FindingsQuery, FindingsStore};
    use tempfile::NamedTempFile;

    fn r(si: &str, ee: &str) -> VersionRange {
        VersionRange { start_including: Some(si.into()), end_excluding: Some(ee.into()), ..Default::default() }
    }

    fn input(id: &str, score: Option<f64>, kev: bool) -> VulnInput {
        VulnInput {
            cve_id: id.into(),
            title: None,
            description: "RouterOS contains an argument-handling flaw in the SSH login path.".into(),
            cvss_score: score,
            cvss_vector: Some("CVSS:4.0/AV:N".into()),
            ranges: vec![r("6.0", "6.49.21"), r("7.0", "7.23.4"), r("7.24", "7.24.2")],
            kev_date_added: kev.then(|| "2026-09-10".to_string()),
            mitigations: Vec::new(),
            source: VulnSource::Nvd,
        }
    }

    #[test]
    fn severity_prefers_kev_then_cvss_bands() {
        assert_eq!(severity_for(Some(5.0), true), FindingSeverity::Critical);
        assert_eq!(severity_for(Some(8.8), false), FindingSeverity::High);
        assert_eq!(severity_for(Some(7.0), false), FindingSeverity::High);
        assert_eq!(severity_for(Some(6.9), false), FindingSeverity::Medium);
        assert_eq!(severity_for(Some(4.0), false), FindingSeverity::Medium);
        assert_eq!(severity_for(Some(3.9), false), FindingSeverity::Low);
        assert_eq!(severity_for(None, false), FindingSeverity::Medium);
    }

    #[test]
    fn kev_listed_affected_cve_is_critical_and_honest_about_scope() {
        let a = assess("dev1", "7.24.1 (stable)", &[input("CVE-2026-86060", Some(9.2), true)], 1);
        assert_eq!(a.affected.len(), 1);
        let f = &a.affected[0];
        assert_eq!(f.finding_id, "dev1:ver:CVE-2026-86060");
        assert_eq!(f.category, VULN_CATEGORY);
        assert_eq!(f.severity, FindingSeverity::Critical);
        assert!(f.title.contains("actively exploited"));
        assert!(f.narrative.contains("Drift has not checked whether the affected feature is enabled"));
        assert!(f.recommended_actions[0].contains("7.24.2"));
        assert!(f.recommended_actions.iter().any(|a| a.contains("nvd.nist.gov/vuln/detail/CVE-2026-86060")));
    }

    #[test]
    fn fixed_version_is_not_affected() {
        let a = assess("dev1", "7.24.2", &[input("CVE-2026-86060", Some(9.2), true)], 1);
        assert!(a.affected.is_empty());
        assert!(a.not_affected.contains("dev1:ver:CVE-2026-86060"));
    }

    #[test]
    fn unparseable_version_is_neither_affected_nor_cleared() {
        let a = assess("dev1", "garbage", &[input("CVE-2026-86060", Some(9.2), true)], 1);
        assert!(a.affected.is_empty());
        assert!(a.not_affected.is_empty());
        assert_eq!(a.cannot_evaluate, vec!["CVE-2026-86060".to_string()]);
    }

    async fn vuln_rows(store: &FindingsStore) -> Vec<ion_drift_storage::Finding> {
        store
            .list_findings(&FindingsQuery { category: Some(VULN_CATEGORY.into()), ..Default::default() })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn reconcile_opens_resolves_and_reopens() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let inputs = [input("CVE-2026-86060", Some(9.2), true)];

        reconcile(&store, &assess("dev1", "7.24.1", &inputs, 1)).await.unwrap();
        assert_eq!(vuln_rows(&store).await[0].status, FindingStatus::Open);

        // Upgraded past the fix point.
        reconcile(&store, &assess("dev1", "7.24.2", &inputs, 2)).await.unwrap();
        let rows = vuln_rows(&store).await;
        assert_eq!(rows[0].status, FindingStatus::Resolved);
        assert!(rows[0].resolution_note.as_deref().unwrap().contains("7.24.2"));

        // Downgraded back into the range.
        reconcile(&store, &assess("dev1", "7.24.1", &inputs, 3)).await.unwrap();
        assert_eq!(vuln_rows(&store).await[0].status, FindingStatus::Open);
    }

    #[tokio::test]
    async fn cannot_evaluate_leaves_an_open_finding_alone() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let inputs = [input("CVE-2026-86060", Some(9.2), true)];
        reconcile(&store, &assess("dev1", "7.24.1", &inputs, 1)).await.unwrap();
        reconcile(&store, &assess("dev1", "garbage", &inputs, 2)).await.unwrap();
        assert_eq!(vuln_rows(&store).await[0].status, FindingStatus::Open);
    }

    #[tokio::test]
    async fn other_devices_are_not_touched() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let inputs = [input("CVE-2026-86060", Some(9.2), true)];
        reconcile(&store, &assess("dev1", "7.24.1", &inputs, 1)).await.unwrap();
        reconcile(&store, &assess("dev2", "7.24.2", &inputs, 2)).await.unwrap();
        let rows = vuln_rows(&store).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, FindingStatus::Open);
    }
}
```
If `ion_drift_storage::Finding` is not re-exported at the crate root (check `sed -n 15,17p crates/ion-drift-storage/src/lib.rs`), use `ion_drift_storage::findings::Finding`.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p ion-drift-web advisory::vulnerable`
Expected: compile FAIL — `cannot find function assess`, `VulnInput`, `severity_for`, `reconcile`.

- [ ] **Step 3: Implement**

Insert above the tests in `vulnerable.rs`:
```rust
//!
//! A finding here says exactly one thing: this device's RouterOS version falls
//! in a published affected range. It does not claim the affected feature is
//! enabled — fetched CVEs carry no machine-readable configuration condition —
//! and every finding's narrative says so.

use std::collections::BTreeSet;

use ion_drift_module_api::{FindingEvidence, FindingSeverity, FindingV1};
use ion_drift_storage::{FindingStatus, FindingsQuery, FindingsStore};
use tracing::warn;

use crate::advisory::exploitation::ADVISORY_MODULE;
use crate::advisory::version::{self, Applicability, VersionRange};

pub(crate) const VULN_CATEGORY: &str = "advisory_vulnerable";

pub(crate) fn vuln_finding_id(device_id: &str, cve_id: &str) -> String {
    format!("{device_id}:ver:{cve_id}")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VulnSource {
    Nvd,
    Catalog,
}

#[derive(Clone, Debug)]
pub(crate) struct VulnInput {
    pub cve_id: String,
    /// Catalog title when curated; `None` for fetched CVEs.
    pub title: Option<String>,
    pub description: String,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub ranges: Vec<VersionRange>,
    pub kev_date_added: Option<String>,
    pub mitigations: Vec<String>,
    pub source: VulnSource,
}

#[derive(Debug, Default)]
pub(crate) struct VulnAssessment {
    pub device_version: String,
    pub affected: Vec<FindingV1>,
    /// Finding ids for CVEs positively evaluated as not affecting this device.
    pub not_affected: BTreeSet<String>,
    /// CVE ids that could not be evaluated. Never resolved, never raised.
    pub cannot_evaluate: Vec<String>,
}

/// KEV-listed → Critical, whatever the score; otherwise CVSS bands.
pub(crate) fn severity_for(cvss: Option<f64>, on_kev: bool) -> FindingSeverity {
    if on_kev {
        return FindingSeverity::Critical;
    }
    match cvss {
        Some(s) if s >= 7.0 => FindingSeverity::High,
        Some(s) if s >= 4.0 => FindingSeverity::Medium,
        Some(_) => FindingSeverity::Low,
        None => FindingSeverity::Medium,
    }
}

pub(crate) fn assess(device_id: &str, device_version: &str, inputs: &[VulnInput], now: i64) -> VulnAssessment {
    let mut out = VulnAssessment { device_version: device_version.to_string(), ..Default::default() };
    for input in inputs {
        let id = vuln_finding_id(device_id, &input.cve_id);
        match version::evaluate(device_version, &input.ranges) {
            (Applicability::Affected, Some(matched)) => {
                out.affected.push(build_finding(&id, device_id, device_version, input, matched, now));
            }
            (Applicability::NotAffected, _) => {
                out.not_affected.insert(id);
            }
            _ => out.cannot_evaluate.push(input.cve_id.clone()),
        }
    }
    out
}

fn upgrade_action(matched: &VersionRange) -> String {
    match (&matched.end_excluding, &matched.end_including) {
        (Some(fixed), _) => format!("Upgrade RouterOS to {fixed} or later on this release branch."),
        (None, Some(last)) => format!("Upgrade RouterOS beyond {last}."),
        _ => "No fixed RouterOS version is recorded for this range; restrict access to the affected feature.".to_string(),
    }
}

fn build_finding(
    finding_id: &str,
    device_id: &str,
    device_version: &str,
    input: &VulnInput,
    matched: &VersionRange,
    now: i64,
) -> FindingV1 {
    let version_label = device_version.split_whitespace().next().unwrap_or(device_version);
    let on_kev = input.kev_date_added.is_some();
    let headline = input.title.clone().unwrap_or_else(|| input.cve_id.clone());
    let exploited = if on_kev { " — actively exploited" } else { "" };
    let attribution = match input.source {
        VulnSource::Nvd => format!("Description from the National Vulnerability Database (NVD), {}.", input.cve_id),
        VulnSource::Catalog => "Description from the Ion Drift advisory catalog.".to_string(),
    };
    let narrative = format!(
        "{}\n\nYour RouterOS version ({version_label}) is in the affected range. Drift has not checked \
         whether the affected feature is enabled on this router.{}\n\n{attribution}",
        input.description,
        match &input.kev_date_added {
            Some(d) => format!(" CISA lists this vulnerability as known to be exploited in the wild (added {d})."),
            None => String::new(),
        },
    );
    let mut recommended_actions = vec![upgrade_action(matched)];
    recommended_actions.extend(input.mitigations.iter().cloned());
    recommended_actions.push(format!("Details: https://nvd.nist.gov/vuln/detail/{}", input.cve_id));

    FindingV1 {
        finding_id: finding_id.to_string(),
        title: format!("{headline} — RouterOS {version_label} is affected{exploited}"),
        narrative,
        severity: severity_for(input.cvss_score, on_kev),
        category: VULN_CATEGORY.to_string(),
        recommended_actions,
        evidence: vec![FindingEvidence::Custom {
            label: "version match".to_string(),
            payload: serde_json::json!({
                "cve_id": input.cve_id,
                "device_id": device_id,
                "device_version": device_version,
                "matched_range": matched,
                "kev_date_added": input.kev_date_added,
            }),
        }],
        device_macs: Vec::new(),
        timestamp_unix: now,
        metadata: Some(serde_json::json!({
            "cve_id": input.cve_id,
            "cvss_score": input.cvss_score,
            "cvss_vector": input.cvss_vector,
            "kev_date_added": input.kev_date_added,
            "source": match input.source { VulnSource::Nvd => "nvd", VulnSource::Catalog => "catalog" },
        })),
    }
}

/// Apply one device's assessment. Resolves only findings for CVEs positively
/// evaluated as not affected; `cannot_evaluate` CVEs are left exactly as they are.
pub(crate) async fn reconcile(store: &FindingsStore, assessment: &VulnAssessment) -> Result<(), String> {
    let held: BTreeSet<String> = store
        .list_findings(&FindingsQuery {
            module_name: Some(ADVISORY_MODULE.to_string()),
            category: Some(VULN_CATEGORY.to_string()),
            ..Default::default()
        })
        .await?
        .into_iter()
        .filter(|f| f.status != FindingStatus::Resolved)
        .map(|f| f.finding_id)
        .collect();

    for finding in &assessment.affected {
        // Re-open first: upsert preserves lifecycle state, so a finding closed
        // after an upgrade would otherwise stay resolved after a downgrade.
        if let Err(e) = store.reopen_by_key(ADVISORY_MODULE, &finding.finding_id).await {
            warn!(finding_id = %finding.finding_id, error = %e, "advisory: vulnerability reopen failed");
        }
        if let Err(e) = store.upsert_finding(ADVISORY_MODULE, finding, None, None).await {
            warn!(finding_id = %finding.finding_id, error = %e, "advisory: vulnerability upsert failed");
        }
    }

    let version_label = assessment.device_version.split_whitespace().next().unwrap_or("");
    let note = format!("No longer affected: RouterOS {version_label} is outside every affected range.");
    for id in assessment.not_affected.intersection(&held) {
        if let Err(e) = store.resolve_by_key(ADVISORY_MODULE, id, &note).await {
            warn!(finding_id = %id, error = %e, "advisory: vulnerability resolve failed");
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p ion-drift-web advisory::vulnerable`
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ion-drift-web/src/advisory/vulnerable.rs crates/ion-drift-web/src/advisory/mod.rs
git commit -m "feat(advisory): version-based vulnerability findings"
```

---

### Task 8: Per-device pass, bundled version constraints, evaluator wiring

**Files:**
- Create: `crates/ion-drift-web/src/advisory/device_pass.rs`
- Modify: `crates/ion-drift-web/src/advisory/mod.rs`, `crates/ion-drift-web/src/advisory/catalog.rs` (`validate`, after the severity check ~line 330; tests), `crates/ion-drift-web/src/tasks/advisory.rs` (after `exploitation::evaluate` ~line 63)

**Interfaces:**
- Consumes: `vulnerable::{assess, reconcile, VulnInput, VulnSource}` (Task 7); `AdvisoryStore::{list_feed_cves, list_feed_kev, list_advisories}`; `RouterQueue::submit(&self, poller_id: &str, Priority, Vec<QueuedRequest>) -> Result<Vec<Result<Value, MikrotikError>>, QueueError>`; `DeviceQueueRegistry::get_or_create(&mut self, device_id: &str, client: &MikrotikClient) -> RouterQueue`; `DeviceEntry { client: DeviceClient, record: DeviceRecord { id, enabled, is_primary, .. } }`.
- Produces: `pub(crate) fn merge_inputs(feed: Vec<FeedCve>, kev: Vec<FeedKev>, catalog: &[AdvisoryRecord]) -> Vec<VulnInput>`; `pub(crate) struct DeviceReads { pub version: Option<String>, pub services: Option<Vec<IpService>> }` (the `services` field is added in Task 11); `pub(crate) fn parse_device_reads<E: Display>(results: &[Result<Value, E>]) -> DeviceReads`; `pub(crate) async fn evaluate_devices(state: &AppState) -> Result<(), String>`.

- [ ] **Step 1: Write the failing tests**

(a) Catalog — append inside `mod tests` in `advisory/catalog.rs`:
```rust
    #[tokio::test]
    async fn version_constraint_ranges_are_accepted() {
        let seed = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let db = TempDir::new().unwrap();
        let body = valid_catalog(1, "api brute force").replace(
            r#""version_constraint": null"#,
            r#""version_constraint": [{"start_including": "7.0", "end_excluding": "7.24.2"}]"#,
        );
        write(&seed, "mikrotik.json", &body);
        let store = store_in(&db).await;
        let report = load_catalog(&store, seed.path(), data.path()).await.expect("load");
        assert!(!report.degraded);
        assert_eq!(report.advisories_loaded, 1);
        let stored = store.list_advisories().await.unwrap();
        let ranges: Vec<crate::advisory::version::VersionRange> =
            serde_json::from_str(stored[0].version_constraint.as_deref().unwrap()).unwrap();
        assert_eq!(ranges[0].end_excluding.as_deref(), Some("7.24.2"));
    }

    #[tokio::test]
    async fn unrecognised_version_constraint_is_rejected() {
        let seed = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let db = TempDir::new().unwrap();
        let body = valid_catalog(1, "api brute force")
            .replace(r#""version_constraint": null"#, r#""version_constraint": "< 7.16""#);
        write(&seed, "mikrotik.json", &body);
        let store = store_in(&db).await;
        let report = load_catalog(&store, seed.path(), data.path()).await.expect("load");
        assert!(report.degraded);
        assert_eq!(report.advisories_loaded, 0);
        assert!(report.files_rejected[0].contains("version_constraint"));
    }
```

(b) Device pass — add `pub mod device_pass;` to `advisory/mod.rs` and create `advisory/device_pass.rs`:
```rust
//! Per-device advisory pass.

#[cfg(test)]
mod tests {
    use super::*;
    use ion_drift_storage::{AdvisoryRecord, FeedCve, FeedKev};

    fn feed(id: &str, ranges_json: &str) -> FeedCve {
        FeedCve {
            cve_id: id.into(), published: "p".into(), last_modified: "m".into(),
            description: "nvd text".into(), cvss_version: Some("4.0".into()), cvss_score: Some(8.8),
            cvss_vector: Some("CVSS:4.0/AV:N".into()), cwe: None, nvd_status: "Analyzed".into(),
            ranges_json: ranges_json.into(),
        }
    }

    fn catalog(id: &str, constraint: Option<&str>) -> AdvisoryRecord {
        AdvisoryRecord {
            advisory_id: id.into(), title: "Curated title".into(), narrative: "curated text".into(),
            severity: "high".into(), requires_surface_class: "service".into(),
            requires_surface_names: vec!["api-ssl".into()], requires_state: vec![],
            version_constraint: constraint.map(Into::into), no_fixed_release: false,
            fixed_versions: vec![], mitigations: vec!["scope the service".into()], references: vec![],
            attack_techniques: vec![], source: "bundled".into(), catalog_version: 1,
            generated_at: "2026-09-24".into(),
        }
    }

    const RANGE: &str = r#"[{"start_including":"7.0","end_excluding":"7.24.2"}]"#;

    #[test]
    fn feed_entries_join_kev() {
        let kev = vec![FeedKev { cve_id: "CVE-2026-86060".into(), date_added: "2026-09-10".into(), due_date: None }];
        let inputs = merge_inputs(vec![feed("CVE-2026-86060", RANGE), feed("CVE-2018-14847", RANGE)], kev, &[]);
        assert_eq!(inputs.len(), 2);
        let k = inputs.iter().find(|i| i.cve_id == "CVE-2026-86060").unwrap();
        assert_eq!(k.kev_date_added.as_deref(), Some("2026-09-10"));
        assert_eq!(k.ranges.len(), 1);
    }

    #[test]
    fn curated_entry_with_constraint_replaces_feed_entry_but_keeps_its_score() {
        let inputs = merge_inputs(
            vec![feed("CVE-2026-86060", RANGE)],
            vec![],
            &[catalog("CVE-2026-86060", Some(RANGE))],
        );
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].source, VulnSource::Catalog);
        assert_eq!(inputs[0].title.as_deref(), Some("Curated title"));
        assert_eq!(inputs[0].cvss_score, Some(8.8));
        assert_eq!(inputs[0].mitigations, vec!["scope the service".to_string()]);
    }

    #[test]
    fn bundled_entry_without_constraint_is_not_a_version_finding() {
        let inputs = merge_inputs(vec![], vec![], &[catalog("CVE-2026-16347", None)]);
        assert!(inputs.is_empty());
    }

    #[test]
    fn corrupt_ranges_become_empty_and_so_cannot_be_evaluated() {
        let inputs = merge_inputs(vec![feed("CVE-2026-86060", "not json")], vec![], &[]);
        assert!(inputs[0].ranges.is_empty());
    }

    #[test]
    fn device_reads_extract_version() {
        let ok: Vec<Result<serde_json::Value, String>> =
            vec![Ok(serde_json::json!({"version": "7.24.1 (stable)", "uptime": "1d"}))];
        assert_eq!(parse_device_reads(&ok).version.as_deref(), Some("7.24.1 (stable)"));
    }

    #[test]
    fn failed_or_missing_version_read_yields_none() {
        let failed: Vec<Result<serde_json::Value, String>> = vec![Err("timeout".into())];
        assert!(parse_device_reads(&failed).version.is_none());
        let empty: Vec<Result<serde_json::Value, String>> = vec![Ok(serde_json::json!({}))];
        assert!(parse_device_reads(&empty).version.is_none());
        let none: Vec<Result<serde_json::Value, String>> = vec![];
        assert!(parse_device_reads(&none).version.is_none());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p ion-drift-web advisory::catalog advisory::device_pass`
Expected: `unrecognised_version_constraint_is_rejected` FAILS (the loader currently accepts the string); device_pass fails to compile (`merge_inputs`, `parse_device_reads` missing).

- [ ] **Step 3: Implement catalog validation**

In `advisory/catalog.rs`, inside `fn validate`, directly after the `KNOWN_SEVERITIES` check:
```rust
    // A constraint is either absent or a non-empty list of version ranges the
    // matcher can evaluate. Anything else is rejected rather than stored and
    // silently ignored: an advisory must never claim coverage the engine
    // cannot compute.
    if let Some(vc) = raw
        .version_constraint
        .as_ref()
        .filter(|v| !v.is_null() && v.as_str().is_none_or(|s| !s.trim().is_empty()))
    {
        let usable = serde_json::from_value::<Vec<crate::advisory::version::VersionRange>>(vc.clone())
            .is_ok_and(|ranges| !ranges.is_empty());
        if !usable {
            return Err((
                advisory_id,
                "unrecognised version_constraint: expected a non-empty array of version ranges".to_string(),
            ));
        }
    }
```

- [ ] **Step 4: Implement the device pass**

Insert above the tests in `advisory/device_pass.rs`:
```rust
//!
//! Each evaluator cycle reads every enabled RouterOS device once — through its
//! router queue, never directly — and reconciles version findings for it. A
//! device whose read fails is skipped for the cycle: a failed read is not
//! evidence of anything, so it can neither raise nor resolve a finding.

use std::collections::BTreeMap;
use std::fmt::Display;

use ion_drift_storage::{AdvisoryRecord, FeedCve, FeedKev};
use serde_json::Value;

use crate::advisory::exploitation::now_unix;
use crate::advisory::version::VersionRange;
use crate::advisory::vulnerable::{self, VulnInput, VulnSource};
use crate::router_queue::{Priority, QueuedRequest, RouterQueue};
use crate::staging::stage_text;
use crate::state::AppState;

/// `router_queue` poller id. Must not collide with another submitter's.
const POLLER_ID: &str = "advisory-device-pass";

/// Fetched CVEs joined with KEV; a bundled advisory that carries a version
/// constraint replaces the feed entry for the same id (curated beats fetched)
/// while keeping the feed's CVSS data. Bundled advisories without a constraint
/// are service-scoped and handled by exposure findings, not here.
pub(crate) fn merge_inputs(feed: Vec<FeedCve>, kev: Vec<FeedKev>, catalog: &[AdvisoryRecord]) -> Vec<VulnInput> {
    let kev: BTreeMap<String, String> = kev.into_iter().map(|k| (k.cve_id, k.date_added)).collect();
    let mut by_id: BTreeMap<String, VulnInput> = BTreeMap::new();
    for c in feed {
        let ranges: Vec<VersionRange> = serde_json::from_str(&c.ranges_json).unwrap_or_default();
        by_id.insert(
            c.cve_id.clone(),
            VulnInput {
                kev_date_added: kev.get(&c.cve_id).cloned(),
                cve_id: c.cve_id,
                title: None,
                description: c.description,
                cvss_score: c.cvss_score,
                cvss_vector: c.cvss_vector,
                ranges,
                mitigations: Vec::new(),
                source: VulnSource::Nvd,
            },
        );
    }
    for a in catalog {
        let Some(ranges) = a
            .version_constraint
            .as_deref()
            .and_then(|vc| serde_json::from_str::<Vec<VersionRange>>(vc).ok())
        else {
            continue;
        };
        let prior = by_id.remove(&a.advisory_id);
        by_id.insert(
            a.advisory_id.clone(),
            VulnInput {
                cve_id: a.advisory_id.clone(),
                title: Some(a.title.clone()),
                description: a.narrative.clone(),
                cvss_score: prior.as_ref().and_then(|p| p.cvss_score),
                cvss_vector: prior.as_ref().and_then(|p| p.cvss_vector.clone()),
                ranges,
                kev_date_added: kev.get(&a.advisory_id).cloned(),
                mitigations: a.mitigations.clone(),
                source: VulnSource::Catalog,
            },
        );
    }
    by_id.into_values().collect()
}

#[derive(Debug, Default)]
pub(crate) struct DeviceReads {
    pub version: Option<String>,
}

/// Results arrive in request order: `[system/resource]`.
pub(crate) fn parse_device_reads<E: Display>(results: &[Result<Value, E>]) -> DeviceReads {
    let version = match results.first() {
        Some(Ok(v)) => v
            .get("version")
            .and_then(Value::as_str)
            .map(|s| stage_text(s, 64))
            .filter(|s| !s.is_empty()),
        _ => None,
    };
    DeviceReads { version }
}

struct Target {
    device_id: String,
    queue: RouterQueue,
}

async fn routeros_targets(state: &AppState) -> Vec<Target> {
    let entries: Vec<(String, bool, mikrotik_core::MikrotikClient)> = {
        let dm = state.device_manager.read().await;
        dm.all_devices()
            .into_iter()
            .filter(|d| d.record.enabled)
            .filter_map(|d| {
                d.client
                    .as_routeros()
                    .map(|c| (d.record.id.clone(), d.record.is_primary, c.clone()))
            })
            .collect()
    };
    let mut out = Vec::with_capacity(entries.len());
    for (device_id, primary, client) in entries {
        let queue = if primary {
            state.router_queue.clone()
        } else {
            state.device_queues.write().await.get_or_create(&device_id, &client)
        };
        out.push(Target { device_id, queue });
    }
    out
}

pub(crate) async fn evaluate_devices(state: &AppState) -> Result<(), String> {
    let catalog = state.advisory_store.list_advisories().await?;
    let inputs = merge_inputs(
        state.advisory_store.list_feed_cves().await?,
        state.advisory_store.list_feed_kev().await?,
        &catalog,
    );
    let now = now_unix();
    for target in routeros_targets(state).await {
        let results = match target
            .queue
            .submit(POLLER_ID, Priority::Low, vec![QueuedRequest::get("system/resource")])
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(device = %target.device_id, error = %e, "advisory: device read failed; findings unchanged");
                continue;
            }
        };
        let reads = parse_device_reads(&results);
        let Some(version) = reads.version else {
            tracing::warn!(device = %target.device_id, "advisory: no RouterOS version read; version findings unchanged");
            continue;
        };
        let assessment = vulnerable::assess(&target.device_id, &version, &inputs, now);
        if !assessment.cannot_evaluate.is_empty() {
            tracing::debug!(device = %target.device_id, count = assessment.cannot_evaluate.len(), "advisory: CVEs not evaluable for this version");
        }
        if let Err(e) = vulnerable::reconcile(&state.findings_store, &assessment).await {
            tracing::warn!(device = %target.device_id, error = %e, "advisory: vulnerability reconcile failed");
        }
    }
    Ok(())
}
```

- [ ] **Step 5: Wire into the evaluator**

In `crates/ion-drift-web/src/tasks/advisory.rs`, directly after the `exploitation::evaluate` block:
```rust
                // Per-device pass (version and, from Task 11, exposure). Runs
                // every cycle whether or not the feed is on: bundled advisories
                // are evaluated either way.
                if let Err(e) = crate::advisory::device_pass::evaluate_devices(&state).await {
                    tracing::warn!(error = %e, "advisory: device pass failed");
                }
```

- [ ] **Step 6: Run the tests**

Run: `cargo test -p ion-drift-web advisory`
Expected: all advisory tests pass, including the existing `version_constraint_flattens_to_json_string`.

- [ ] **Step 7: Commit**

```bash
git add crates/ion-drift-web/src/advisory/device_pass.rs crates/ion-drift-web/src/advisory/mod.rs \
        crates/ion-drift-web/src/advisory/catalog.rs crates/ion-drift-web/src/tasks/advisory.rs
git commit -m "feat(advisory): per-device version pass wired into the evaluator"
```

---

## Phase C — Exposure findings

### Task 9: `/ip/service` resource

**Files:**
- Modify: `crates/mikrotik-core/src/resources/ip.rs` (struct near the other `/ip` types; method inside `impl MikrotikClient` ~line 205; tests module ~line 257)

**Interfaces:**
- Produces: `pub struct IpService { pub id: String, pub name: String, pub port: Option<u32>, pub disabled: bool, pub address: Option<String>, pub invalid: Option<bool> }`; `MikrotikClient::ip_services(&self) -> Result<Vec<IpService>, MikrotikError>`.

- [ ] **Step 1: Write the failing tests**

Append inside `mod tests` in `resources/ip.rs`:
```rust
    #[test]
    fn ip_service_deserializes_router_payload() {
        let payload = serde_json::json!([
            { ".id": "*8", "address": "", "certificate": "none", "disabled": "false",
              "invalid": "false", "name": "api-ssl", "port": "8729", "tls-version": "any", "vrf": "main" },
            { ".id": "*3", "address": "192.168.1.17/32", "disabled": "true", "name": "api", "port": "8728" }
        ]);
        let svcs: Vec<IpService> = serde_json::from_value(payload).unwrap();
        assert_eq!(svcs[0].name, "api-ssl");
        assert_eq!(svcs[0].port, Some(8729));
        assert!(!svcs[0].disabled);
        assert_eq!(svcs[0].address.as_deref(), Some(""));
        assert_eq!(svcs[1].address.as_deref(), Some("192.168.1.17/32"));
        assert!(svcs[1].disabled);
    }

    #[test]
    fn ip_service_tolerates_missing_optionals() {
        let payload = serde_json::json!([{ ".id": "*1", "name": "ssh", "disabled": "false" }]);
        let svcs: Vec<IpService> = serde_json::from_value(payload).unwrap();
        assert!(svcs[0].port.is_none());
        assert!(svcs[0].address.is_none());
        assert!(svcs[0].invalid.is_none());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p mikrotik-core ip_service`
Expected: compile FAIL — `cannot find type IpService`.

- [ ] **Step 3: Implement**

Add near the other structs in `resources/ip.rs`:
```rust
/// IP service — `/ip/service` (api, api-ssl, ssh, telnet, ftp, www, www-ssl, winbox).
///
/// `address` is the service's own source restriction: empty means any address
/// that can reach the router may connect.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct IpService {
    #[serde(rename = ".id")]
    pub id: String,
    pub name: String,
    #[serde(default, deserialize_with = "ros_u32_opt")]
    pub port: Option<u32>,
    #[serde(deserialize_with = "ros_bool")]
    pub disabled: bool,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub invalid: Option<bool>,
}
```
Inside `impl MikrotikClient`, after `dns_config`:
```rust
    /// `/ip/service` — management services and their source restrictions.
    pub async fn ip_services(&self) -> Result<Vec<IpService>, MikrotikError> {
        self.get("ip/service").await
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p mikrotik-core ip_service`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/mikrotik-core/src/resources/ip.rs
git commit -m "feat(mikrotik): IpService resource for /ip/service"
```

---

### Task 10: Reopen an acknowledged finding

**Files:**
- Modify: `crates/ion-drift-storage/src/findings.rs` (method after `reopen_by_key` ~line 522; tests module)

**Interfaces:**
- Produces: `FindingsStore::reopen_acknowledged_by_key(&self, module_name: &str, finding_id: &str) -> Result<bool, String>` — `acknowledged` → `open`, clears ack stamps; `Ok(false)` for any other status.

- [ ] **Step 1: Write the failing test**

Append inside the tests module of `findings.rs` (add `use tempfile::NamedTempFile;` and `use ion_drift_module_api::{FindingSeverity, FindingV1};` to that module if not already imported):
```rust
    fn escalation_finding(id: &str) -> FindingV1 {
        FindingV1 {
            finding_id: id.into(),
            title: "t".into(),
            narrative: "n".into(),
            severity: FindingSeverity::Low,
            category: "advisory_exposure".into(),
            recommended_actions: vec![],
            evidence: vec![],
            device_macs: vec![],
            timestamp_unix: 1,
            metadata: None,
        }
    }

    #[tokio::test]
    async fn reopen_acknowledged_by_key_only_touches_acknowledged_rows() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let id = store.upsert_finding("advisory", &escalation_finding("x:exposure"), None, None).await.unwrap();

        // Open → untouched.
        assert!(!store.reopen_acknowledged_by_key("advisory", "x:exposure").await.unwrap());

        store.acknowledge(id, "scott").await.unwrap();
        assert!(store.reopen_acknowledged_by_key("advisory", "x:exposure").await.unwrap());
        let row = store.get_finding(id).await.unwrap().unwrap();
        assert_eq!(row.status, FindingStatus::Open);
        assert!(row.acknowledged_by.is_none());
        assert!(row.acknowledged_at.is_none());

        // Resolved → untouched (that is reopen_by_key's job).
        store.resolve_by_key("advisory", "x:exposure", "gone").await.unwrap();
        assert!(!store.reopen_acknowledged_by_key("advisory", "x:exposure").await.unwrap());
    }
```
Check the single-row getter's name first: `grep -nE 'pub async fn get_finding|pub async fn get_by_id|pub async fn get\(' crates/ion-drift-storage/src/findings.rs`. If it is not `get_finding(id) -> Result<Option<Finding>, String>`, use `list_findings(&FindingsQuery::default())` and take the row with `finding_id == "x:exposure"` instead.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p ion-drift-storage reopen_acknowledged`
Expected: compile FAIL — `no method named reopen_acknowledged_by_key`.

- [ ] **Step 3: Implement**

After `reopen_by_key` in `findings.rs`:
```rust
    /// Re-open an *acknowledged* finding whose condition an engine has seen
    /// get worse. Acknowledgement accepts the risk the operator saw, not a
    /// larger one; when the engine escalates severity it calls this so the
    /// finding returns to the open queue.
    ///
    /// Only an `acknowledged` row changes. Ack stamps are cleared — they
    /// belonged to the lesser condition. Returns `Ok(false)` when no row
    /// matched, so repeated calls are idempotent.
    pub async fn reopen_acknowledged_by_key(
        &self,
        module_name: &str,
        finding_id: &str,
    ) -> Result<bool, String> {
        let db = self.db.lock().await;
        let updated = db
            .execute(
                "UPDATE findings
                 SET status = 'open',
                     acknowledged_at = NULL,
                     acknowledged_by = NULL
                 WHERE module_name = ?1
                   AND finding_id = ?2
                   AND status = 'acknowledged'",
                params![module_name, finding_id],
            )
            .map_err(|e| format!("reopen_acknowledged_by_key failed: {e}"))?;
        Ok(updated > 0)
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p ion-drift-storage findings`
Expected: new test passes; existing findings tests unchanged.

- [ ] **Step 5: Commit**

```bash
git add crates/ion-drift-storage/src/findings.rs
git commit -m "feat(storage): reopen acknowledged findings on escalation"
```

---

### Task 11: Exposure findings + wiring

**Files:**
- Create: `crates/ion-drift-web/src/advisory/exposure.rs`
- Modify: `crates/ion-drift-web/src/advisory/mod.rs`, `crates/ion-drift-web/src/advisory/device_pass.rs` (`DeviceReads`, `parse_device_reads`, `evaluate_devices`, tests)

**Interfaces:**
- Consumes: `IpService` (Task 9); `FindingsStore::reopen_acknowledged_by_key` (Task 10); `exploitation::{surface_key, ADVISORY_MODULE}`; `staging::{stage_service, stage_addresses}`.
- Produces: `pub(crate) const EXPOSURE_CATEGORY: &str = "advisory_exposure"`; `pub(crate) fn exposure_finding_id(device_id, service, advisory_id) -> String` (`<device>:svc:<service>:<advisory>:exposure`); `pub(crate) enum Scope { Unrestricted, Restricted(Vec<String>) }`; `pub(crate) fn scope_of(Option<&str>) -> Scope`; `pub(crate) struct ExposureAssessment { exposed: Vec<FindingV1>, not_exposed: BTreeSet<String> }`; `pub(crate) fn assess(device_id, &[IpService], &[AdvisoryRecord], now) -> ExposureAssessment`; `pub(crate) async fn reconcile(&FindingsStore, ExposureAssessment) -> Result<(), String>`; `DeviceReads.services: Option<Vec<IpService>>`.

- [ ] **Step 1: Write the failing tests**

Add `pub mod exposure;` to `advisory/mod.rs`. Create `advisory/exposure.rs`:
```rust
//! Service exposure findings.

#[cfg(test)]
mod tests {
    use super::*;
    use ion_drift_storage::{FindingStatus, FindingsQuery, FindingsStore};
    use tempfile::NamedTempFile;

    fn svc(name: &str, disabled: bool, address: Option<&str>) -> IpService {
        serde_json::from_value(serde_json::json!({
            ".id": "*1", "name": name, "port": "8729",
            "disabled": if disabled { "true" } else { "false" },
            "address": address,
        }))
        .unwrap()
    }

    fn advisory() -> AdvisoryRecord {
        AdvisoryRecord {
            advisory_id: "CVE-2026-16347".into(), title: "RouterOS API accepts unlimited login attempts".into(),
            narrative: "catalog narrative".into(), severity: "high".into(),
            requires_surface_class: "service".into(),
            requires_surface_names: vec!["api".into(), "api-ssl".into()],
            requires_state: vec![], version_constraint: None, no_fixed_release: true,
            fixed_versions: vec![], mitigations: vec!["/ip/service set api-ssl address=<mgmt-cidr>".into()],
            references: vec![], attack_techniques: vec![], source: "bundled".into(),
            catalog_version: 2, generated_at: "2026-07-28".into(),
        }
    }

    const ID: &str = "dev1:svc:api-ssl:CVE-2026-16347:exposure";

    #[test]
    fn scope_classification() {
        assert_eq!(scope_of(None), Scope::Unrestricted);
        assert_eq!(scope_of(Some("")), Scope::Unrestricted);
        assert_eq!(scope_of(Some("0.0.0.0/0")), Scope::Unrestricted);
        assert_eq!(scope_of(Some("192.168.1.17/32,0.0.0.0/0")), Scope::Unrestricted);
        assert_eq!(scope_of(Some("::/0")), Scope::Unrestricted);
        assert_eq!(scope_of(Some("192.168.1.17/32")), Scope::Restricted(vec!["192.168.1.17/32".into()]));
    }

    #[test]
    fn unrestricted_enabled_service_is_high() {
        let a = assess("dev1", &[svc("api-ssl", false, Some(""))], &[advisory()], 1);
        assert_eq!(a.exposed.len(), 1);
        let f = &a.exposed[0];
        assert_eq!(f.finding_id, ID);
        assert_eq!(f.category, EXPOSURE_CATEGORY);
        assert_eq!(f.severity, FindingSeverity::High);
        assert!(f.narrative.contains("no attack has been observed"));
        // api is absent, so its surface counts as not exposed.
        assert!(a.not_exposed.contains("dev1:svc:api:CVE-2026-16347:exposure"));
    }

    #[test]
    fn restricted_enabled_service_is_low_with_scope_in_evidence() {
        let a = assess("dev1", &[svc("api-ssl", false, Some("192.168.1.17/32"))], &[advisory()], 1);
        let f = &a.exposed[0];
        assert_eq!(f.severity, FindingSeverity::Low);
        let ion_drift_module_api::FindingEvidence::Custom { payload, .. } = &f.evidence[0] else {
            panic!("expected custom evidence")
        };
        assert_eq!(payload["scope"], serde_json::json!(["192.168.1.17/32"]));
    }

    #[test]
    fn disabled_service_is_not_exposed() {
        let a = assess("dev1", &[svc("api-ssl", true, Some(""))], &[advisory()], 1);
        assert!(a.exposed.is_empty());
        assert!(a.not_exposed.contains(ID));
    }

    #[test]
    fn unrelated_service_raises_nothing() {
        let a = assess("dev1", &[svc("ssh", false, Some(""))], &[advisory()], 1);
        assert!(a.exposed.is_empty());
    }

    async fn rows(store: &FindingsStore) -> Vec<ion_drift_storage::Finding> {
        store.list_findings(&FindingsQuery { category: Some(EXPOSURE_CATEGORY.into()), ..Default::default() }).await.unwrap()
    }

    #[tokio::test]
    async fn exposure_ceases_when_service_is_disabled() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        reconcile(&store, assess("dev1", &[svc("api-ssl", false, Some(""))], &[advisory()], 1)).await.unwrap();
        reconcile(&store, assess("dev1", &[svc("api-ssl", true, Some(""))], &[advisory()], 2)).await.unwrap();
        let r = rows(&store).await;
        assert_eq!(r[0].status, FindingStatus::Resolved);
        assert!(r[0].resolution_note.as_deref().unwrap().contains("Exposure ceased"));
    }

    #[tokio::test]
    async fn acknowledged_low_reopens_when_widened_to_unrestricted() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        reconcile(&store, assess("dev1", &[svc("api-ssl", false, Some("192.168.1.17/32"))], &[advisory()], 1)).await.unwrap();
        store.acknowledge(rows(&store).await[0].id, "scott").await.unwrap();

        reconcile(&store, assess("dev1", &[svc("api-ssl", false, Some(""))], &[advisory()], 2)).await.unwrap();
        let r = rows(&store).await;
        assert_eq!(r[0].status, FindingStatus::Open);
        assert_eq!(r[0].severity, FindingSeverity::High);
        assert!(r[0].narrative.contains("Escalated from low to high"));
    }

    #[tokio::test]
    async fn acknowledged_finding_stays_acknowledged_while_config_is_unchanged() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let reads = [svc("api-ssl", false, Some("192.168.1.17/32"))];
        reconcile(&store, assess("dev1", &reads, &[advisory()], 1)).await.unwrap();
        store.acknowledge(rows(&store).await[0].id, "scott").await.unwrap();
        reconcile(&store, assess("dev1", &reads, &[advisory()], 2)).await.unwrap();
        assert_eq!(rows(&store).await[0].status, FindingStatus::Acknowledged);
    }

    #[tokio::test]
    async fn exposure_vulnerability_and_exploitation_coexist() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let mut other = assess("dev1", &[svc("api-ssl", false, Some(""))], &[advisory()], 1).exposed.remove(0);
        for (id, cat) in [
            ("dev1:svc:api-ssl:CVE-2026-16347:exploit", "advisory_exploitation"),
            ("dev1:ver:CVE-2026-86060", "advisory_vulnerable"),
        ] {
            other.finding_id = id.into();
            other.category = cat.into();
            store.upsert_finding(ADVISORY_MODULE, &other, None, None).await.unwrap();
        }
        reconcile(&store, assess("dev1", &[svc("api-ssl", false, Some(""))], &[advisory()], 2)).await.unwrap();
        let all = store
            .list_findings(&FindingsQuery { module_name: Some(ADVISORY_MODULE.into()), ..Default::default() })
            .await
            .unwrap();
        assert_eq!(all.len(), 3);
        assert!(all.iter().all(|f| f.status == FindingStatus::Open));
    }
}
```
Also add to `mod tests` in `device_pass.rs`:
```rust
    #[test]
    fn device_reads_extract_services() {
        let ok: Vec<Result<serde_json::Value, String>> = vec![
            Ok(serde_json::json!({"version": "7.24.1"})),
            Ok(serde_json::json!([{ ".id": "*8", "name": "api-ssl", "disabled": "false", "address": "" }])),
        ];
        let reads = parse_device_reads(&ok);
        assert_eq!(reads.services.unwrap()[0].name, "api-ssl");
    }

    #[test]
    fn failed_service_read_yields_none_so_exposure_is_left_alone() {
        let partial: Vec<Result<serde_json::Value, String>> =
            vec![Ok(serde_json::json!({"version": "7.24.1"})), Err("timeout".into())];
        let reads = parse_device_reads(&partial);
        assert!(reads.version.is_some());
        assert!(reads.services.is_none());
        let malformed: Vec<Result<serde_json::Value, String>> =
            vec![Ok(serde_json::json!({"version": "7.24.1"})), Ok(serde_json::json!({"not": "a list"}))];
        assert!(parse_device_reads(&malformed).services.is_none());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p ion-drift-web advisory::exposure advisory::device_pass`
Expected: compile FAIL — `cannot find function assess` (exposure), `no field services on DeviceReads`.

- [ ] **Step 3: Implement `exposure.rs`**

Insert above the tests:
```rust
//!
//! "Your configuration makes this advisory reachable." For every bundled
//! advisory scoped to named services, an enabled service is an exposure.
//! Severity follows the service's own `address` restriction: reachable from
//! anywhere is High, restricted to listed sources is Low. Exposure is reported
//! alongside exploitation and vulnerability findings, never instead of them.

use std::collections::{BTreeMap, BTreeSet};

use ion_drift_module_api::{FindingEvidence, FindingSeverity, FindingV1};
use ion_drift_storage::{AdvisoryRecord, FindingStatus, FindingsQuery, FindingsStore};
use mikrotik_core::resources::ip::IpService;
use tracing::warn;

use crate::advisory::exploitation::{surface_key, ADVISORY_MODULE};
use crate::staging::{stage_addresses, stage_service};

pub(crate) const EXPOSURE_CATEGORY: &str = "advisory_exposure";
const CEASED_NOTE: &str =
    "Exposure ceased: the service is disabled or no longer present on this device.";

pub(crate) fn exposure_finding_id(device_id: &str, service: &str, advisory_id: &str) -> String {
    format!("{}:{advisory_id}:exposure", surface_key(device_id, service))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    Unrestricted,
    Restricted(Vec<String>),
}

/// Any open entry (`0.0.0.0/0`, `::/0`) or an empty list means unrestricted.
pub(crate) fn scope_of(address: Option<&str>) -> Scope {
    let raw: Vec<String> = address.unwrap_or("").split(',').map(str::to_owned).collect();
    let list = stage_addresses(&raw);
    if list.is_empty() || list.iter().any(|a| a == "0.0.0.0/0" || a == "::/0") {
        Scope::Unrestricted
    } else {
        Scope::Restricted(list)
    }
}

#[derive(Debug, Default)]
pub(crate) struct ExposureAssessment {
    pub exposed: Vec<FindingV1>,
    /// Finding ids for advisory surfaces present in the catalog but not enabled.
    pub not_exposed: BTreeSet<String>,
}

pub(crate) fn assess(
    device_id: &str,
    services: &[IpService],
    catalog: &[AdvisoryRecord],
    now: i64,
) -> ExposureAssessment {
    let enabled: BTreeMap<String, &IpService> = services
        .iter()
        .filter(|s| !s.disabled)
        .map(|s| (stage_service(&s.name), s))
        .collect();
    let mut out = ExposureAssessment::default();
    for adv in catalog.iter().filter(|a| a.requires_surface_class == "service") {
        for name in &adv.requires_surface_names {
            let id = exposure_finding_id(device_id, name, &adv.advisory_id);
            match enabled.get(name.as_str()) {
                Some(svc) => out.exposed.push(build_finding(&id, device_id, svc, adv, now)),
                None => {
                    out.not_exposed.insert(id);
                }
            }
        }
    }
    out
}

fn build_finding(finding_id: &str, device_id: &str, svc: &IpService, adv: &AdvisoryRecord, now: i64) -> FindingV1 {
    let service = stage_service(&svc.name);
    let scope = scope_of(svc.address.as_deref());
    let (severity, reach, scope_json) = match &scope {
        Scope::Unrestricted => (
            FindingSeverity::High,
            "from any address that can reach the router".to_string(),
            serde_json::json!("unrestricted"),
        ),
        Scope::Restricted(list) => (
            FindingSeverity::Low,
            format!("only from {}", list.join(", ")),
            serde_json::json!(list),
        ),
    };
    let port = svc.port.map(|p| p.to_string()).unwrap_or_else(|| "default".to_string());
    FindingV1 {
        finding_id: finding_id.to_string(),
        title: format!("{} — exposed on {service}", adv.title),
        narrative: format!(
            "{}\n\nThe {service} service is enabled on this router (port {port}) and accepts \
             connections {reach}. This is the configuration the advisory applies to; no attack has \
             been observed. Exploitation, if it occurs, is reported as a separate finding.",
            adv.narrative
        ),
        severity,
        category: EXPOSURE_CATEGORY.to_string(),
        recommended_actions: adv.mitigations.clone(),
        evidence: vec![FindingEvidence::Custom {
            label: "service exposure".to_string(),
            payload: serde_json::json!({
                "advisory_id": adv.advisory_id,
                "device_id": device_id,
                "service": service,
                "port": svc.port,
                "scope": scope_json,
                "observed_at_unix": now,
            }),
        }],
        device_macs: Vec::new(),
        timestamp_unix: now,
        metadata: Some(serde_json::json!({
            "advisory_id": adv.advisory_id,
            "references": adv.references,
            "no_fixed_release": adv.no_fixed_release,
            "fixed_versions": adv.fixed_versions,
            "catalog_version": adv.catalog_version,
            "source": adv.source,
        })),
    }
}

fn rank(s: FindingSeverity) -> u8 {
    match s {
        FindingSeverity::Critical => 4,
        FindingSeverity::High => 3,
        FindingSeverity::Medium => 2,
        FindingSeverity::Low => 1,
        FindingSeverity::Info => 0,
    }
}

fn label(s: FindingSeverity) -> &'static str {
    match s {
        FindingSeverity::Critical => "critical",
        FindingSeverity::High => "high",
        FindingSeverity::Medium => "medium",
        FindingSeverity::Low => "low",
        FindingSeverity::Info => "info",
    }
}

/// Apply one device's exposure assessment. Called only after a successful
/// `/ip/service` read.
pub(crate) async fn reconcile(store: &FindingsStore, assessment: ExposureAssessment) -> Result<(), String> {
    let held: BTreeMap<String, (FindingStatus, FindingSeverity)> = store
        .list_findings(&FindingsQuery {
            module_name: Some(ADVISORY_MODULE.to_string()),
            category: Some(EXPOSURE_CATEGORY.to_string()),
            ..Default::default()
        })
        .await?
        .into_iter()
        .map(|f| (f.finding_id, (f.status, f.severity)))
        .collect();

    for mut finding in assessment.exposed {
        match held.get(&finding.finding_id) {
            Some((FindingStatus::Acknowledged, prior)) if rank(finding.severity) > rank(*prior) => {
                finding.narrative.push_str(&format!(
                    "\n\nEscalated from {} to {}: the service's address restriction was removed or \
                     widened after this finding was acknowledged, so it has been reopened for review.",
                    label(*prior),
                    label(finding.severity)
                ));
                if let Err(e) = store.reopen_acknowledged_by_key(ADVISORY_MODULE, &finding.finding_id).await {
                    warn!(finding_id = %finding.finding_id, error = %e, "advisory: exposure escalation reopen failed");
                }
            }
            Some((FindingStatus::Resolved, _)) => {
                if let Err(e) = store.reopen_by_key(ADVISORY_MODULE, &finding.finding_id).await {
                    warn!(finding_id = %finding.finding_id, error = %e, "advisory: exposure reopen failed");
                }
            }
            _ => {}
        }
        if let Err(e) = store.upsert_finding(ADVISORY_MODULE, &finding, None, None).await {
            warn!(finding_id = %finding.finding_id, error = %e, "advisory: exposure upsert failed");
        }
    }

    for id in &assessment.not_exposed {
        if matches!(held.get(id), Some((FindingStatus::Open | FindingStatus::Acknowledged, _))) {
            if let Err(e) = store.resolve_by_key(ADVISORY_MODULE, id, CEASED_NOTE).await {
                warn!(finding_id = %id, error = %e, "advisory: exposure resolve failed");
            }
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Extend the device pass**

In `advisory/device_pass.rs`:

Add the import `use mikrotik_core::resources::ip::IpService;` and `use crate::advisory::exposure;`.

Replace `DeviceReads` and `parse_device_reads` with:
```rust
#[derive(Debug, Default)]
pub(crate) struct DeviceReads {
    pub version: Option<String>,
    /// `None` when the read failed or was malformed — never an empty list, so
    /// a failed read cannot look like "every service disabled".
    pub services: Option<Vec<IpService>>,
}

/// Results arrive in request order: `[system/resource, ip/service]`.
pub(crate) fn parse_device_reads<E: Display>(results: &[Result<Value, E>]) -> DeviceReads {
    let version = match results.first() {
        Some(Ok(v)) => v
            .get("version")
            .and_then(Value::as_str)
            .map(|s| stage_text(s, 64))
            .filter(|s| !s.is_empty()),
        _ => None,
    };
    let services = match results.get(1) {
        Some(Ok(v)) => serde_json::from_value::<Vec<IpService>>(v.clone()).ok(),
        _ => None,
    };
    DeviceReads { version, services }
}
```

Replace the per-device loop body in `evaluate_devices` (from `let results = match target` to the end of the loop) with:
```rust
        let results = match target
            .queue
            .submit(
                POLLER_ID,
                Priority::Low,
                vec![QueuedRequest::get("system/resource"), QueuedRequest::get("ip/service")],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(device = %target.device_id, error = %e, "advisory: device read failed; findings unchanged");
                continue;
            }
        };
        let reads = parse_device_reads(&results);

        match reads.version {
            Some(version) => {
                let assessment = vulnerable::assess(&target.device_id, &version, &inputs, now);
                if !assessment.cannot_evaluate.is_empty() {
                    tracing::debug!(device = %target.device_id, count = assessment.cannot_evaluate.len(), "advisory: CVEs not evaluable for this version");
                }
                if let Err(e) = vulnerable::reconcile(&state.findings_store, &assessment).await {
                    tracing::warn!(device = %target.device_id, error = %e, "advisory: vulnerability reconcile failed");
                }
            }
            None => tracing::warn!(device = %target.device_id, "advisory: no RouterOS version read; version findings unchanged"),
        }

        match reads.services {
            Some(services) => {
                let assessment = exposure::assess(&target.device_id, &services, &catalog, now);
                if let Err(e) = exposure::reconcile(&state.findings_store, assessment).await {
                    tracing::warn!(device = %target.device_id, error = %e, "advisory: exposure reconcile failed");
                }
            }
            None => tracing::warn!(device = %target.device_id, "advisory: /ip/service read failed; exposure findings unchanged"),
        }
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p ion-drift-web advisory`
Expected: all advisory tests pass (exposure 9, device_pass 8).

- [ ] **Step 6: Commit**

```bash
git add crates/ion-drift-web/src/advisory/exposure.rs crates/ion-drift-web/src/advisory/mod.rs \
        crates/ion-drift-web/src/advisory/device_pass.rs
git commit -m "feat(advisory): service exposure findings with escalation reopen"
```

---

## Phase D — Surfacing, docs, verification

### Task 12: Stale/off banner, disclosure docs, full verification

**Files:**
- Create: `web/src/components/advisory-feed-status-banner.tsx`, `web/src/components/__tests__/advisory-feed-status-banner.test.tsx`
- Modify: `web/src/routes/findings.tsx` (imports; after the `<PageShell …>` opening ~line 335), `README.md`, `data/advisories/README.md`, `CHANGELOG.md` (`[Unreleased]`)

**Interfaces:**
- Consumes: `useAdvisoryFeedStatus()` (Task 6).
- Produces: `AdvisoryFeedStatusBanner` component.

- [ ] **Step 1: Write the failing tests**

Create `web/src/components/__tests__/advisory-feed-status-banner.test.tsx`:
```tsx
import { screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AdvisoryFeedStatusBanner } from "../advisory-feed-status-banner";
import { mockFetchRoutes, renderWithClient } from "@/test/utils";

const base = { set_by: "scott", set_at: 1_758_700_000, sources: [], stale: false };

describe("AdvisoryFeedStatusBanner", () => {
  it("warns when the feed is off", async () => {
    mockFetchRoutes({ "GET /api/advisory/feed": { ...base, consent: "off" } });
    renderWithClient(<AdvisoryFeedStatusBanner />);
    expect(await screen.findByRole("status")).toHaveTextContent(/only advisories bundled with this release/i);
  });

  it("warns when data is stale and shows the last error", async () => {
    mockFetchRoutes({
      "GET /api/advisory/feed": {
        ...base,
        consent: "on",
        stale: true,
        sources: [{ source: "nvd", last_success_at: 1_758_000_000, last_attempt_at: 1_758_700_000, last_error: "HTTP 503", records: 83 }],
      },
    });
    renderWithClient(<AdvisoryFeedStatusBanner />);
    const banner = await screen.findByRole("status");
    expect(banner).toHaveTextContent(/stale since/i);
    expect(banner).toHaveTextContent("HTTP 503");
  });

  it("is silent when the feed is on and fresh", async () => {
    mockFetchRoutes({ "GET /api/advisory/feed": { ...base, consent: "on" } });
    const { container } = renderWithClient(<AdvisoryFeedStatusBanner />);
    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd web && npx vitest run src/components/__tests__/advisory-feed-status-banner.test.tsx`
Expected: FAIL — cannot resolve `../advisory-feed-status-banner`.

- [ ] **Step 3: Implement and mount**

Create `web/src/components/advisory-feed-status-banner.tsx`:
```tsx
import { useAdvisoryFeedStatus } from "@/api/queries";

/**
 * Findings-page notice for the two states where "no vulnerability findings"
 * must not be read as "no vulnerabilities": feed off, and feed data stale.
 */
export function AdvisoryFeedStatusBanner() {
  const { data } = useAdvisoryFeedStatus();
  if (!data) return null;

  if (data.consent === "off") {
    return (
      <div role="status" className="mb-4 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-200">
        The vulnerability feed is off. Only advisories bundled with this release are evaluated; newly published
        RouterOS vulnerabilities are not reported. Change this in Settings → Security.
      </div>
    );
  }

  if (data.consent === "on" && data.stale) {
    const failing = data.sources.filter((s) => s.last_error);
    const oldest = data.sources
      .map((s) => s.last_success_at)
      .reduce<number | null>((min, t) => (t == null ? min : min == null ? t : Math.min(min, t)), null);
    return (
      <div role="status" className="mb-4 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-200">
        Vulnerability data stale since {oldest == null ? "first fetch" : new Date(oldest * 1000).toLocaleString()}.
        {failing.map((s) => (
          <span key={s.source}> {s.source.toUpperCase()} last error: {s.last_error}.</span>
        ))}
      </div>
    );
  }

  return null;
}
```
In `web/src/routes/findings.tsx`, add `import { AdvisoryFeedStatusBanner } from "@/components/advisory-feed-status-banner";` with the component imports, and change
```tsx
      isRefreshing={findingsQ.isFetching}
    >
      <div className="mb-4 space-y-3">
```
to
```tsx
      isRefreshing={findingsQ.isFetching}
    >
      <AdvisoryFeedStatusBanner />
      <div className="mb-4 space-y-3">
```

- [ ] **Step 4: Run frontend tests**

Run: `cd web && npx vitest run src/components/__tests__/advisory-feed-status-banner.test.tsx && npx tsc --noEmit && npm test`
Expected: 3 new tests pass; existing Findings tests still pass (their unmocked `GET /api/advisory/feed` 404s and the banner renders nothing).

- [ ] **Step 5: Documentation**

(a) `README.md` — add after the License section's preceding section (before `## License`):
```markdown
## Outbound connections

Ion Drift is self-hosted and sends no telemetry. With one exception, it only talks to devices you configure.

The **vulnerability feed** downloads public RouterOS vulnerability data once a day from:

- `services.nvd.nist.gov` — NIST National Vulnerability Database
- `www.cisa.gov` — CISA Known Exploited Vulnerabilities catalog

These are plain HTTPS downloads; nothing about your installation, network, or devices is sent. The feed is
on by default, but **no request is made until an administrator confirms it** in the dialog shown at first
login. It can be turned off at any time in **Settings → Security**; with it off, only advisories bundled with
the installed release are evaluated.
```
(b) `data/advisories/README.md` — add under **Rules**:
```markdown
- **`version_constraint` is `null` or a non-empty array of ranges.** Each range is an object with any of
  `start_including`, `start_excluding`, `end_including`, `end_excluding`, `exact` — the same shape the NVD
  feed produces, e.g. `[{"start_including": "7.0", "end_excluding": "7.24.2"}]`. Anything else (including
  the old `"< 7.16"` string form) is rejected at load and degrades the catalog. An advisory with a
  constraint raises a version finding on every device in range; one without a constraint raises only
  service-exposure and exploitation findings.
```
(c) `CHANGELOG.md` — under `## [Unreleased]`:
```markdown
### Added

- **Vulnerability feed.** Daily NVD + CISA KEV pull for RouterOS. Every managed RouterOS device whose version
  falls in a published affected range gets a finding; CVEs CISA lists as exploited in the wild are Critical.
  Findings state plainly that Drift checked the version, not whether the affected feature is enabled.
- **Mandatory feed consent.** Administrators confirm the feed (on by default) or turn it off, with a warning,
  before any outbound request is made. Settings → Security shows who decided and when.
- **Service exposure findings.** Bundled advisories scoped to a service (CVE-2026-16347: `api`/`api-ssl`)
  now raise an early-warning finding when the service is enabled — High when reachable from anywhere, Low
  when restricted by `address` — without waiting for an attack. An acknowledged finding reopens if the
  restriction is later removed.
- **Feed health.** Findings shows a banner when the feed is off or its data is more than three days old.

### Changed

- Advisory catalog `version_constraint` must now be `null` or an array of version ranges.
```

- [ ] **Step 6: Full verification (show real output)**

```bash
# openssl workaround env from Global Constraints must be exported first on dev-primary
cargo test --workspace 2>&1 | tail -30
cargo-deny check 2>&1 | tail -10          # must be cargo-deny >= 0.20
cd web && npx tsc --noEmit && npm test 2>&1 | tail -20
```
Expected: all green. Record the test totals in the final commit message body.

- [ ] **Step 7: Commit**

```bash
git add web/src/components/advisory-feed-status-banner.tsx web/src/components/__tests__/advisory-feed-status-banner.test.tsx \
        web/src/routes/findings.tsx README.md data/advisories/README.md CHANGELOG.md
git commit -m "feat(web): feed health banner; document outbound connections"
```

- [ ] **Step 8: Live check on the dev box (Scott)**

Rebuild **from source** — the dev box compose file must use `build: .` (see `docker-compose.build.yml`), not the `image:` registry tag:
```bash
docker compose -f docker-compose.build.yml build --no-cache && docker compose -f docker-compose.build.yml up -d
docker compose -f docker-compose.build.yml logs -f ion-drift | grep -iE 'advisory|feed'
```
1. Log in as admin → the consent dialog appears and cannot be dismissed. Choose **Keep on**.
2. Within ~5 minutes the log shows `advisory feed cycle complete` with `nvd: Some(Ok(N))`, `kev: Some(Ok(4))`.
3. Within one evaluator cycle (≤ 15 min after the feed completes), **Findings** shows:
   - `CVE-2026-86060` and `CVE-2026-67277` as **Critical** for every router below 7.24.2 / 7.23.4 / 6.49.21;
   - the CVE-2026-16347 **exposure** finding for `api-ssl` (Low if scoped to the cert client, High if not).
4. Settings → Security shows "On — set by <you> on <time>" and per-source last-success times.
