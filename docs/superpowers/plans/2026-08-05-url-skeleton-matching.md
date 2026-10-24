# URL Skeleton Matching (Confusable-Domain Detector) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect DNS names on the network whose UTS #39 `skeleton()` collides with a watchlist of brands worth impersonating (`paypa1.com`, `rnicrosoft.com`, Cyrillic lookalikes), by polling the router's DNS cache and emitting findings.

**Architecture:** Un-parks the 2026-08-04 design (workspace note `projects/ion-drift/confusable-domain-detection-2026-08-04.md`) with the input-source decision now made: **poll `/ip/dns/cache` in core** (decided 2026-08-05). Built in core as a second catalog-driven detector — NOT a Module-API module — reusing the advisory engine's discipline: two-tier catalog (bundled seed + operator overlay), untrusted-input handling (warn-and-skip, upsert-never-delete, no panic on input), supervised poller with windowed retention + prune. The DNS observation table is independently valuable: it is the name→IP join key that can later give Sankey/Investigation/World Map real hostnames.

**Tech Stack:** Rust workspace at `<repo>`, branch `development`. New deps in `ion-drift-web`: `unicode-security = "0.1"` (UTS #39 skeleton), `idna = "1"` (punycode → Unicode; currently only transitive). rusqlite store (new `dns.db`), RouterQueue, TaskSupervisor, FindingsStore.

## Global Constraints

- Branch `development`; Conventional Commits; TDD with RED proven first.
- Windowed counting + prune, NO EWMA (ADR PATTERNS).
- Catalog JSON is untrusted third-party data: malformed files are warn-logged and skipped, rows upserted never deleted, no input path may panic, all writes bind parameters (mirror `advisory/catalog.rs` discipline exactly).
- Detection state has one writer: the DNS cache poller writes `dns_observation`; the catalog loader writes `confusable_watchlist`; nothing else writes either.
- The skeleton detector is script-agnostic — it must NOT special-case "non-Latin characters" (browsers solved the mixed-script address-bar case in ~2017; the value is skeleton collision, which also catches pure-ASCII lookalikes).
- New config keys must be added to `config/server.example.toml` in the same commit (a config-docs test enforces example/`config.rs` agreement — verify with the full test suite).
- `cargo test --workspace` green and `cargo deny check` ok before claiming done (new deps must clear the tracked cargo-deny policy).

## Known Limitations (accepted for v1, restate in module docs)

- Only devices using the router as resolver appear in `/ip/dns/cache`; Drift's DNS deviation detection already identifies the ones that don't.
- Suffix matching flags `paypa1.com` and `login.paypa1.com`, but not brand-embedding like `paypal.com.evil.com` (skeleton of the registrable suffix differs). Label-window scanning is future work.
- Watchlist updates do not retro-scan previously observed names (findings emerge on the next observation of the name). GitHub feed refresh is explicitly out of scope (see bottom).

## File Structure

| File | Responsibility |
|---|---|
| `crates/mikrotik-core/src/resources/ip.rs` (modify) | `DnsCacheEntry` + `dns_cache()` fetch |
| `crates/ion-drift-storage/src/dns.rs` (create) | `DnsStore` (`dns.db`): `dns_observation` + `confusable_watchlist` tables |
| `crates/ion-drift-storage/src/lib.rs` (modify) | register `pub mod dns` |
| `crates/ion-drift-web/src/confusable/mod.rs` (create) | module docs + submodule wiring |
| `crates/ion-drift-web/src/confusable/skeleton.rs` (create) | normalize + UTS #39 skeleton + candidate suffixes (pure) |
| `crates/ion-drift-web/src/confusable/catalog.rs` (create) | watchlist loader: seed dir + operator overlay |
| `crates/ion-drift-web/src/confusable/detector.rs` (create) | skeleton index + matcher + finding builder (pure core) |
| `crates/ion-drift-web/src/tasks/dns_cache.rs` (create) | supervised poller: fetch cache → upsert observations → match → emit findings → prune |
| `crates/ion-drift-web/src/{main,state}.rs`, `src/tasks/mod.rs` (modify) | store init, catalog load at startup, AppState field, spawn |
| `crates/ion-drift-web/src/modules_registry/service.rs:299` (modify) | reserve module name `"confusable"` |
| `seed/confusable/baseline.json` (create; confirm base dir against `advisory_seed_dir()` at `main.rs:1087`) | bundled brand watchlist |
| `crates/ion-drift-web/src/config.rs`, `config/server.example.toml` (modify) | `dns_cache_interval_secs` (default 300) |

---

### Task 1: `/ip/dns/cache` fetch in mikrotik-core

**Files:**
- Modify: `crates/mikrotik-core/src/resources/ip.rs` (struct next to `DnsStaticEntry` at `:84`; method next to `dns_static()` at `:204`)

**Interfaces:**
- Produces (Task 6 relies on): `pub struct DnsCacheEntry { pub id: String, pub name: String, pub data: Option<String>, pub record_type: Option<String>, pub ttl: Option<String>, pub is_static: Option<bool> }` and `pub async fn dns_cache(&self) -> ...` on the same resource client that owns `dns_static()` (match its exact receiver and return type).

- [ ] **Step 1: Write the failing deserialization test** (in ip.rs's test module; mirror however `DnsStaticEntry`'s deserialization is tested — if untested, this is the first, keep the same fixture style):

```rust
    #[test]
    fn dns_cache_entry_deserializes_router_payload() {
        let payload = serde_json::json!([{
            ".id": "*1",
            "name": "paypa1.com",
            "data": "203.0.113.9",
            "type": "A",
            "ttl": "23h59m59s",
            "static": "false"
        }]);
        let entries: Vec<DnsCacheEntry> = serde_json::from_value(payload).unwrap();
        assert_eq!(entries[0].name, "paypa1.com");
        assert_eq!(entries[0].data.as_deref(), Some("203.0.113.9"));
        assert_eq!(entries[0].record_type.as_deref(), Some("A"));
        assert_eq!(entries[0].is_static, Some(false));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mikrotik-core dns_cache_entry -- --nocapture`
Expected: FAIL to compile — `DnsCacheEntry` not found.

- [ ] **Step 3: Implement**

```rust
/// DNS cache entry — `/ip/dns/cache`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DnsCacheEntry {
    #[serde(rename = ".id")]
    pub id: String,
    pub name: String,
    /// Resolved payload: an IP for A/AAAA, a target name for CNAME.
    #[serde(default)]
    pub data: Option<String>,
    #[serde(rename = "type", default)]
    pub record_type: Option<String>,
    /// RouterOS duration string, e.g. "23h59m59s".
    #[serde(default)]
    pub ttl: Option<String>,
    #[serde(rename = "static", default, deserialize_with = "ros_bool_opt")]
    pub is_static: Option<bool>,
}
```

and next to `dns_static()`:

```rust
    /// Fetch the DNS cache — every name the router has resolved recently.
    pub async fn dns_cache(&self) -> Result<Vec<DnsCacheEntry>, Error> {
        self.get("ip/dns/cache").await
    }
```

(Copy the exact `Result`/`Error` types from `dns_static()` one page up — do not invent new ones.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mikrotik-core dns_cache_entry`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mikrotik-core/src/resources/ip.rs
git commit -m "feat(mikrotik): DnsCacheEntry + /ip/dns/cache fetch"
```

---

### Task 2: `DnsStore` — observations + watchlist

**Files:**
- Create: `crates/ion-drift-storage/src/dns.rs`
- Modify: `crates/ion-drift-storage/src/lib.rs` (add `pub mod dns;` and re-exports matching how `advisory` is re-exported)

**Interfaces:**
- Consumes: `crate::migrations::open_guard` (same open path as `AdvisoryStore::new` at `advisory.rs:111`).
- Produces (Tasks 4–6 rely on):
  - `pub struct DnsObservation { pub name: String, pub skeleton: String, pub addresses: Vec<String>, pub first_seen: i64, pub last_seen: i64 }`
  - `pub struct WatchlistEntry { pub domain: String, pub brand: String, pub skeleton: String, pub allow: bool, pub source: String, pub catalog_version: i64 }`
  - `pub struct DnsStore` with `pub const SCHEMA_VERSION: u32 = 1;` and:
    - `pub async fn new(db_path: &Path) -> Result<Self, String>`
    - `pub async fn upsert_observation(&self, name: &str, skeleton: &str, addresses: &[String], now: i64) -> Result<bool, String>` (returns `true` when the name is new)
    - `pub async fn prune_observations(&self, cutoff: i64) -> Result<usize, String>` (deletes `last_seen < cutoff`)
    - `pub async fn upsert_watchlist_entry(&self, e: &WatchlistEntry) -> Result<(), String>` (higher `catalog_version` wins; equal version = last write wins, so an operator file layers over a bundled file of the same version — advisory merge semantics)
    - `pub async fn list_watchlist(&self) -> Result<Vec<WatchlistEntry>, String>`

Baseline DDL (fresh v1 — no versioned steps yet, mirror `AdvisoryStore`'s `CREATE TABLE IF NOT EXISTS` baseline block):

```sql
CREATE TABLE IF NOT EXISTS dns_observation (
    name TEXT PRIMARY KEY,
    skeleton TEXT NOT NULL,
    addresses TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dns_observation_skeleton ON dns_observation(skeleton);
CREATE INDEX IF NOT EXISTS idx_dns_observation_last_seen ON dns_observation(last_seen);

CREATE TABLE IF NOT EXISTS confusable_watchlist (
    domain TEXT PRIMARY KEY,
    brand TEXT NOT NULL,
    skeleton TEXT NOT NULL,
    allow INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL,
    catalog_version INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_confusable_watchlist_skeleton ON confusable_watchlist(skeleton);
```

- [ ] **Step 1: Write the failing tests**

```rust
    #[tokio::test]
    async fn observation_upsert_reports_new_then_updates_in_place() {
        let f = NamedTempFile::new().unwrap();
        let store = DnsStore::new(f.path()).await.unwrap();

        let new = store
            .upsert_observation("paypa1.com", "paypal.com", &["203.0.113.9".into()], 100)
            .await
            .unwrap();
        assert!(new, "first sighting is new");

        let again = store
            .upsert_observation("paypa1.com", "paypal.com", &["203.0.113.10".into()], 200)
            .await
            .unwrap();
        assert!(!again, "second sighting refreshes, not re-creates");

        let rows = store.observations_since(0).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].first_seen, 100, "first_seen survives the refresh");
        assert_eq!(rows[0].last_seen, 200);
        assert_eq!(rows[0].addresses, vec!["203.0.113.10"], "addresses follow the latest sighting");
    }

    #[tokio::test]
    async fn prune_observations_deletes_only_stale_names() {
        let f = NamedTempFile::new().unwrap();
        let store = DnsStore::new(f.path()).await.unwrap();
        store.upsert_observation("old.example", "old.example", &[], 100).await.unwrap();
        store.upsert_observation("new.example", "new.example", &[], 300).await.unwrap();
        let deleted = store.prune_observations(200).await.unwrap();
        assert_eq!(deleted, 1);
        let left = store.observations_since(0).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].name, "new.example");
    }

    #[tokio::test]
    async fn watchlist_merge_higher_version_wins_tie_goes_to_later_write() {
        let f = NamedTempFile::new().unwrap();
        let store = DnsStore::new(f.path()).await.unwrap();
        let mk = |brand: &str, version: i64, source: &str| WatchlistEntry {
            domain: "paypal.com".into(),
            brand: brand.into(),
            skeleton: "paypal.com".into(),
            allow: false,
            source: source.into(),
            catalog_version: version,
        };
        store.upsert_watchlist_entry(&mk("PayPal v2", 2, "bundled")).await.unwrap();
        store.upsert_watchlist_entry(&mk("stale v1", 1, "operator")).await.unwrap();
        let list = store.list_watchlist().await.unwrap();
        assert_eq!(list[0].brand, "PayPal v2", "lower version must not clobber");

        store.upsert_watchlist_entry(&mk("operator v2", 2, "operator")).await.unwrap();
        let list = store.list_watchlist().await.unwrap();
        assert_eq!(list[0].brand, "operator v2", "same version: later write (operator overlay) wins");
    }
```

(Add `pub async fn observations_since(&self, cutoff: i64) -> Result<Vec<DnsObservation>, String>` — the tests above use it and the future Sankey join will too; `WHERE last_seen >= ?1 ORDER BY last_seen DESC`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ion-drift-storage dns -- --nocapture`
Expected: FAIL to compile — module `dns` not found.

- [ ] **Step 3: Implement** — open path copies `AdvisoryStore::new` (open, `open_guard` with `SCHEMA_VERSION`, WAL pragmas, baseline `execute_batch`). `upsert_observation` in one lock:

```rust
    pub async fn upsert_observation(
        &self,
        name: &str,
        skeleton: &str,
        addresses: &[String],
        now: i64,
    ) -> Result<bool, String> {
        let addresses_json =
            serde_json::to_string(addresses).map_err(|e| format!("serialize addresses: {e}"))?;
        let db = self.db.lock().await;
        let updated = db
            .execute(
                "UPDATE dns_observation SET addresses = ?2, last_seen = ?3, skeleton = ?4
                 WHERE name = ?1",
                params![name, addresses_json, now, skeleton],
            )
            .map_err(|e| format!("observation update failed: {e}"))?;
        if updated > 0 {
            return Ok(false);
        }
        db.execute(
            "INSERT INTO dns_observation (name, skeleton, addresses, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?4)",
            params![name, skeleton, addresses_json, now],
        )
        .map_err(|e| format!("observation insert failed: {e}"))?;
        Ok(true)
    }
```

`upsert_watchlist_entry` merge:

```rust
        db.execute(
            "INSERT INTO confusable_watchlist
                (domain, brand, skeleton, allow, source, catalog_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(domain) DO UPDATE SET
                brand = excluded.brand,
                skeleton = excluded.skeleton,
                allow = excluded.allow,
                source = excluded.source,
                catalog_version = excluded.catalog_version
             WHERE excluded.catalog_version >= confusable_watchlist.catalog_version",
            params![e.domain, e.brand, e.skeleton, e.allow as i64, e.source, e.catalog_version],
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ion-drift-storage dns`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ion-drift-storage/src/dns.rs crates/ion-drift-storage/src/lib.rs
git commit -m "feat(storage): DnsStore with dns_observation + confusable_watchlist"
```

---

### Task 3: Skeleton primitives (pure)

**Files:**
- Create: `crates/ion-drift-web/src/confusable/mod.rs`, `crates/ion-drift-web/src/confusable/skeleton.rs`
- Modify: `crates/ion-drift-web/src/main.rs` line 1 area (`mod confusable;`), `crates/ion-drift-web/Cargo.toml` (add `unicode-security = "0.1"`, `idna = "1"`)

**Interfaces:**
- Produces (Tasks 4–6 rely on):
  - `pub(crate) fn normalize_domain(raw: &str) -> String` — trim, strip trailing dot, lowercase, punycode→Unicode
  - `pub(crate) fn skeleton_of(domain: &str) -> String` — UTS #39 skeleton
  - `pub(crate) fn candidate_suffixes(name: &str) -> Vec<String>` — last 2, 3, 4 labels (shortest first), only suffixes with ≥2 labels

- [ ] **Step 1: Write the failing tests** (in skeleton.rs)

```rust
    #[test]
    fn ascii_lookalikes_share_a_skeleton() {
        assert_eq!(skeleton_of("paypa1.com"), skeleton_of("paypal.com"), "1 vs l");
        assert_eq!(skeleton_of("rnicrosoft.com"), skeleton_of("microsoft.com"), "rn vs m");
        assert_ne!(skeleton_of("example.com"), skeleton_of("paypal.com"));
    }

    #[test]
    fn cross_script_lookalikes_share_a_skeleton() {
        // Cyrillic а (U+0430) in place of Latin a.
        assert_eq!(skeleton_of("аpple.com"), skeleton_of("apple.com"));
    }

    #[test]
    fn normalize_decodes_punycode_and_case() {
        // xn--pple-43d.com is аpple.com (Cyrillic а).
        assert_eq!(normalize_domain("XN--PPLE-43D.COM."), "аpple.com");
        assert_eq!(normalize_domain("Login.PayPal.com"), "login.paypal.com");
    }

    #[test]
    fn candidate_suffixes_shortest_first_min_two_labels() {
        assert_eq!(
            candidate_suffixes("a.b.c.d.e"),
            vec!["d.e".to_string(), "c.d.e".into(), "b.c.d.e".into()],
            "last 2..=4 labels"
        );
        assert_eq!(candidate_suffixes("paypal.com"), vec!["paypal.com".to_string()]);
        assert!(candidate_suffixes("localhost").is_empty(), "single label: nothing to match");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ion-drift-web confusable::skeleton -- --nocapture`
Expected: FAIL to compile — module not found.

- [ ] **Step 3: Implement**

```rust
//! UTS #39 skeleton primitives — pure string functions, no I/O.
//!
//! Script-agnostic on purpose: browsers have enforced mixed-script display
//! rules since ~2017, so "contains Cyrillic" detects nothing an attacker still
//! uses in the address bar. Skeleton collision also catches the pure-ASCII
//! lookalikes browsers deliberately allow (paypa1.com, rnicrosoft.com).

/// Canonical form for comparison: trimmed, no trailing dot, lowercased,
/// punycode labels decoded to Unicode so `xn--pple-43d.com` and the raw
/// Cyrillic form skeleton identically.
pub(crate) fn normalize_domain(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('.').to_lowercase();
    let (unicode, _result) = idna::domain_to_unicode(&trimmed);
    // A label idna cannot decode comes back best-effort; never panic on
    // attacker-controlled input.
    unicode
}

/// UTS #39 confusable skeleton. Two domains are confusable iff equal here.
pub(crate) fn skeleton_of(domain: &str) -> String {
    unicode_security::confusable_detection::skeleton(domain).collect()
}

/// The suffixes worth matching against a watchlist of registrable domains:
/// the last 2..=4 labels, shortest first, so `paypal.com` is checked before
/// `login.paypal.com` and an exact brand match short-circuits as legitimate.
pub(crate) fn candidate_suffixes(name: &str) -> Vec<String> {
    let labels: Vec<&str> = name.split('.').filter(|l| !l.is_empty()).collect();
    (2..=4)
        .filter(|n| *n <= labels.len())
        .map(|n| labels[labels.len() - n..].join("."))
        .collect()
}
```

`mod.rs`:

```rust
//! Confusable / homograph domain detection — a second catalog-driven detector.
//!
//! Like the advisory engine, core carries no watchlist content: brands arrive
//! as catalog data (bundled seed + operator overlay) and land in `dns.db`.
//! Core only knows how to normalize a name, compute a UTS #39 skeleton, and
//! compare — adding a brand is a catalog edit, never a code change.

pub mod catalog;
pub mod detector;
pub mod skeleton;
```

(`catalog`/`detector` arrive in Tasks 4–5; create them as empty files with the module doc line now so this compiles, or add the `pub mod` lines in their tasks — either way each commit compiles.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ion-drift-web confusable::skeleton`
Expected: 4 passed. If the `unicode_security` path differs in the released 0.1.x (e.g. `skeleton` re-exported at crate root), follow the compiler — the collected-`String` contract stays identical.

- [ ] **Step 5: Verify licence policy**

Run: `cargo deny check`
Expected: ok — `unicode-security`/`idna` are Unicode-3.0/MIT/Apache-2.0 family; if cargo-deny objects, add the licence to `deny.toml`'s allow list in this same commit with a comment, do not skip the check.

- [ ] **Step 6: Commit**

```bash
git add crates/ion-drift-web/src/confusable/ crates/ion-drift-web/src/main.rs crates/ion-drift-web/Cargo.toml Cargo.lock
git commit -m "feat(confusable): UTS-39 skeleton primitives (unicode-security + idna)"
```

---

### Task 4: Watchlist catalog loader + bundled seed

**Files:**
- Create: `crates/ion-drift-web/src/confusable/catalog.rs`
- Create: bundled seed `confusable/baseline.json` under the same base directory `advisory_seed_dir()` (`main.rs:1087`) resolves — read that function first and place the file so a source checkout and the container (`/app/seed/`) both find it; env override `DRIFT_CONFUSABLE_SEED_DIR` mirrors `DRIFT_ADVISORY_SEED_DIR`.

**Interfaces:**
- Consumes: `DnsStore::{upsert_watchlist_entry, list_watchlist}` (Task 2), `skeleton::{normalize_domain, skeleton_of}` (Task 3).
- Produces (Task 6 relies on):
  - `pub struct WatchlistLoadReport { pub entries_loaded: usize, pub files_rejected: Vec<String>, pub degraded: bool }`
  - `pub async fn load_watchlist(store: &DnsStore, seed_dir: &Path, data_dir: &Path) -> Result<WatchlistLoadReport, String>`

File format (documented at the top of catalog.rs):

```json
{
  "catalog_version": 1,
  "entries": [
    { "brand": "PayPal", "domain": "paypal.com" },
    { "brand": "Example Corp allowlisted lookalike", "domain": "examp1e-corp.com", "allow": true }
  ]
}
```

Loader rules, copied from `advisory/catalog.rs` behaviour:
- Read `seed_dir` (`source = "bundled"`) then `data_dir` (`source = "operator"`); merge by `domain` — version/tie semantics live in the store upsert (Task 2).
- Unreadable/malformed file → `warn!`, push into `files_rejected`, `degraded = true`, continue.
- Per-entry validation: `domain` non-empty after `normalize_domain`, must contain at least one dot (`candidate_suffixes` cannot match a single label); a bad entry costs that entry, not the file.
- Skeleton computed at load time (`skeleton_of(&normalize_domain(&domain))`) so storage and matching never recompute or disagree.
- Rows upserted, never deleted: a bad load degrades to last-known-good.

- [ ] **Step 1: Write the failing tests** (tempdir seed + data dirs, same fixture style as `advisory/catalog.rs:454` onward)

```rust
    #[tokio::test]
    async fn loads_seed_then_operator_overlay() {
        let seed = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(
            seed.path().join("baseline.json"),
            r#"{"catalog_version":1,"entries":[{"brand":"PayPal","domain":"paypal.com"}]}"#,
        )
        .unwrap();
        std::fs::write(
            data.path().join("local.json"),
            r#"{"catalog_version":1,"entries":[{"brand":"Our Bank","domain":"examplebank.com"}]}"#,
        )
        .unwrap();
        let f = NamedTempFile::new().unwrap();
        let store = DnsStore::new(f.path()).await.unwrap();
        let report = load_watchlist(&store, seed.path(), data.path()).await.unwrap();
        assert_eq!(report.entries_loaded, 2);
        assert!(!report.degraded);
        let list = store.list_watchlist().await.unwrap();
        let sources: Vec<&str> = list.iter().map(|e| e.source.as_str()).collect();
        assert!(sources.contains(&"bundled") && sources.contains(&"operator"));
        assert!(list.iter().all(|e| !e.skeleton.is_empty()), "skeleton computed at load");
    }

    #[tokio::test]
    async fn malformed_file_degrades_without_stopping_the_load() {
        let seed = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(seed.path().join("bad.json"), "{truncated").unwrap();
        std::fs::write(
            seed.path().join("good.json"),
            r#"{"catalog_version":1,"entries":[{"brand":"GitHub","domain":"github.com"}]}"#,
        )
        .unwrap();
        let f = NamedTempFile::new().unwrap();
        let store = DnsStore::new(f.path()).await.unwrap();
        let report = load_watchlist(&store, seed.path(), data.path()).await.unwrap();
        assert!(report.degraded);
        assert_eq!(report.entries_loaded, 1, "good file still lands");
        assert_eq!(report.files_rejected.len(), 1);
    }

    #[tokio::test]
    async fn single_label_domain_costs_the_entry_not_the_file() {
        let seed = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(
            seed.path().join("mixed.json"),
            r#"{"catalog_version":1,"entries":[
                {"brand":"bad","domain":"localhost"},
                {"brand":"GitHub","domain":"github.com"}]}"#,
        )
        .unwrap();
        let f = NamedTempFile::new().unwrap();
        let store = DnsStore::new(f.path()).await.unwrap();
        let report = load_watchlist(&store, seed.path(), data.path()).await.unwrap();
        assert_eq!(report.entries_loaded, 1);
        assert_eq!(store.list_watchlist().await.unwrap()[0].domain, "github.com");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ion-drift-web confusable::catalog -- --nocapture`
Expected: FAIL to compile — `load_watchlist` not found.

- [ ] **Step 3: Implement** — structure mirrors `advisory/catalog.rs`: `RawWatchlistFile { catalog_version: i64, entries: Vec<RawWatchlistEntry> }`, `RawWatchlistEntry { brand: String, domain: String, #[serde(default)] allow: bool }`; iterate `[(seed_dir, "bundled"), (data_dir, "operator")]`; reuse its `json_files`-style directory scan (missing directory = empty, not an error).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ion-drift-web confusable::catalog`
Expected: 3 passed.

- [ ] **Step 5: Write the bundled seed** — `baseline.json` with `catalog_version: 1` and an initial brand set worth impersonating for this deployment's users: `paypal.com`, `microsoft.com`, `microsoftonline.com`, `google.com`, `apple.com`, `icloud.com`, `amazon.com`, `netflix.com`, `facebook.com`, `github.com`, `linkedin.com`, `dropbox.com`, `chase.com`, `wellsfargo.com`, `coinbase.com`. (The highest-value tier is operator additions — own domains, the org's SaaS — which ship empty by design.)

- [ ] **Step 6: Commit**

```bash
git add crates/ion-drift-web/src/confusable/catalog.rs seed/confusable/baseline.json
git commit -m "feat(confusable): watchlist catalog loader + bundled baseline"
```

---

### Task 5: Detector core (pure) + finding builder

**Files:**
- Create: `crates/ion-drift-web/src/confusable/detector.rs`

**Interfaces:**
- Consumes: `WatchlistEntry` (Task 2), `skeleton::{skeleton_of, candidate_suffixes}` (Task 3), `ion_drift_module_api::{FindingEvidence, FindingSeverity, FindingV1}`.
- Produces (Task 6 relies on):
  - `pub(crate) const CONFUSABLE_MODULE: &str = "confusable";`
  - `pub(crate) const CONFUSABLE_CATEGORY: &str = "confusable_domain";`
  - `pub(crate) struct WatchIndex` with `pub fn build(entries: &[WatchlistEntry]) -> Self` and `pub fn match_name(&self, normalized_name: &str) -> Option<ConfusableHit>`
  - `pub(crate) struct ConfusableHit { pub observed: String, pub matched_suffix: String, pub watchlist_domain: String, pub brand: String }`
  - `pub(crate) fn build_finding(hit: &ConfusableHit, addresses: &[String], now: i64) -> FindingV1`

Matching rule (the heart of the feature):
1. For each candidate suffix of the observed name, **shortest first**: if the suffix string-equals a watchlist domain → the name IS the brand (or its subdomain) → return `None` immediately.
2. Otherwise, if the suffix's skeleton equals a watchlist entry's skeleton: an `allow: true` entry suppresses (`None`); a normal entry returns the hit.
3. No suffix matches → `None`.

- [ ] **Step 1: Write the failing tests**

```rust
    fn entry(brand: &str, domain: &str, allow: bool) -> WatchlistEntry {
        WatchlistEntry {
            domain: domain.into(),
            brand: brand.into(),
            skeleton: crate::confusable::skeleton::skeleton_of(domain),
            allow,
            source: "bundled".into(),
            catalog_version: 1,
        }
    }

    #[test]
    fn flags_ascii_lookalike_and_names_the_brand() {
        let idx = WatchIndex::build(&[entry("PayPal", "paypal.com", false)]);
        let hit = idx.match_name("paypa1.com").expect("must flag");
        assert_eq!(hit.watchlist_domain, "paypal.com");
        assert_eq!(hit.brand, "PayPal");
        assert_eq!(hit.matched_suffix, "paypa1.com");
    }

    #[test]
    fn flags_lookalike_under_a_subdomain() {
        let idx = WatchIndex::build(&[entry("PayPal", "paypal.com", false)]);
        let hit = idx.match_name("login.paypa1.com").expect("must flag the suffix");
        assert_eq!(hit.matched_suffix, "paypa1.com");
    }

    #[test]
    fn never_flags_the_brand_itself_or_its_subdomains() {
        let idx = WatchIndex::build(&[entry("PayPal", "paypal.com", false)]);
        assert!(idx.match_name("paypal.com").is_none());
        assert!(idx.match_name("www.paypal.com").is_none());
    }

    #[test]
    fn allow_entry_suppresses_the_collision() {
        let idx = WatchIndex::build(&[
            entry("PayPal", "paypal.com", false),
            entry("our own test domain", "paypa1.com", true),
        ]);
        assert!(idx.match_name("paypa1.com").is_none(), "operator allowlisted");
    }

    #[test]
    fn finding_id_is_stable_per_pair() {
        let hit = ConfusableHit {
            observed: "paypa1.com".into(),
            matched_suffix: "paypa1.com".into(),
            watchlist_domain: "paypal.com".into(),
            brand: "PayPal".into(),
        };
        let a = build_finding(&hit, &["203.0.113.9".into()], 100);
        let b = build_finding(&hit, &["203.0.113.10".into()], 200);
        assert_eq!(a.finding_id, b.finding_id, "re-observation refines, never re-mints");
        assert_eq!(a.category, "confusable_domain");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ion-drift-web confusable::detector -- --nocapture`
Expected: FAIL to compile.

- [ ] **Step 3: Implement**

```rust
pub(crate) struct WatchIndex {
    by_skeleton: BTreeMap<String, Vec<WatchlistEntry>>,
    exact_domains: BTreeSet<String>,
}

impl WatchIndex {
    pub fn build(entries: &[WatchlistEntry]) -> Self {
        let mut by_skeleton: BTreeMap<String, Vec<WatchlistEntry>> = BTreeMap::new();
        let mut exact_domains = BTreeSet::new();
        for e in entries {
            exact_domains.insert(e.domain.clone());
            by_skeleton.entry(e.skeleton.clone()).or_default().push(e.clone());
        }
        Self { by_skeleton, exact_domains }
    }

    pub fn match_name(&self, normalized_name: &str) -> Option<ConfusableHit> {
        for suffix in candidate_suffixes(normalized_name) {
            // The brand itself (or its subdomain) is the one name that must
            // never be flagged — its skeleton collides with itself by
            // definition. Shortest-first ordering makes this check hit before
            // any longer suffix could.
            if self.exact_domains.contains(&suffix) {
                return None;
            }
            if let Some(entries) = self.by_skeleton.get(&skeleton_of(&suffix)) {
                if entries.iter().any(|e| e.allow) {
                    return None;
                }
                if let Some(e) = entries.first() {
                    return Some(ConfusableHit {
                        observed: normalized_name.to_string(),
                        matched_suffix: suffix,
                        watchlist_domain: e.domain.clone(),
                        brand: e.brand.clone(),
                    });
                }
            }
        }
        None
    }
}
```

`build_finding` follows `exploitation::build_finding`'s shape (`exploitation.rs:447`):

```rust
pub(crate) fn build_finding(hit: &ConfusableHit, addresses: &[String], now: i64) -> FindingV1 {
    FindingV1 {
        // Stable per (brand-domain, observed-name): a name seen again refines
        // the existing finding rather than minting a second one to triage.
        finding_id: format!("confusable:{}:{}", hit.watchlist_domain, hit.observed),
        title: format!(
            "Confusable domain — {} resembles {}",
            hit.observed, hit.watchlist_domain
        ),
        narrative: format!(
            "A device on the network resolved {observed}, whose UTS #39 skeleton is \
             identical to {domain} ({brand}). Visually-confusable registrations are the \
             standard delivery mechanism for credential phishing; browsers only police \
             this inside the address bar, not in mail clients, chat, or terminals. \
             Verify which device asked for it and why.",
            observed = hit.observed,
            domain = hit.watchlist_domain,
            brand = hit.brand,
        ),
        severity: FindingSeverity::High,
        category: CONFUSABLE_CATEGORY.to_string(),
        recommended_actions: vec![
            format!("Identify the device that resolved {} (DNS cache / connection history)", hit.observed),
            "If unexpected, block the domain at the firewall and check the device for phishing exposure".to_string(),
            format!("If this is a legitimate domain, add it to the operator watchlist overlay with \"allow\": true"),
        ],
        evidence: vec![FindingEvidence::Custom {
            label: "dns observation".to_string(),
            payload: serde_json::json!({
                "observed_name": hit.observed,
                "matched_suffix": hit.matched_suffix,
                "watchlist_domain": hit.watchlist_domain,
                "brand": hit.brand,
                "resolved_addresses": addresses,
            }),
        }],
        device_macs: Vec::new(),
        timestamp_unix: now,
        metadata: Some(serde_json::json!({
            "watchlist_domain": hit.watchlist_domain,
            "brand": hit.brand,
        })),
    }
}
```

(Check `FindingSeverity`'s variants in `ion-drift-module-api` — use `High`; `KNOWN_SEVERITIES` in advisory/catalog.rs confirms "high" exists in the vocabulary.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ion-drift-web confusable::detector`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ion-drift-web/src/confusable/detector.rs crates/ion-drift-web/src/confusable/mod.rs
git commit -m "feat(confusable): skeleton watch-index matcher + finding builder"
```

---

### Task 6: Poller task + startup wiring + reserved name + config

**Files:**
- Create: `crates/ion-drift-web/src/tasks/dns_cache.rs`
- Modify: `crates/ion-drift-web/src/tasks/mod.rs` (register + spawn), `crates/ion-drift-web/src/state.rs` (AppState field), `crates/ion-drift-web/src/main.rs` (store init + watchlist load + seed-dir helper), `crates/ion-drift-web/src/modules_registry/service.rs:299`, `crates/ion-drift-web/src/config.rs` (`PollingConfig`), `config/server.example.toml`

**Interfaces:**
- Consumes: everything above; `TaskSupervisor::spawn` (pattern: `tasks/advisory.rs:25`), `RouterQueue::submit` + per-result deserialize (pattern: `tasks/policy_sync.rs:101-140`), `FindingsStore::upsert_finding(module, &finding, None, None)` (pattern: `exploitation.rs:319`).
- Produces: running end-to-end feature.

- [ ] **Step 1: Reserve the module name** — `modules_registry/service.rs:299`:

```rust
const RESERVED_MODULE_NAMES: &[&str] = &["advisory", "in-process", "confusable"];
```

Run: `cargo test -p ion-drift-web reserved_names_rejected` — the existing test loops the list, so it covers the new name with no test edit. Expected: PASS.

- [ ] **Step 2: Config key** — in `PollingConfig` (`config.rs:34`):

```rust
    /// DNS cache harvest for confusable-domain detection.
    #[serde(default = "default_dns_cache_interval")]
    pub dns_cache_interval_secs: u64,
```

with `fn default_dns_cache_interval() -> u64 { 300 }` next to `default_policy_sync_interval()` (`config.rs:83`), the field initialised in the `Default` impl (`config.rs:71` area), and in `config/server.example.toml` under `[polling]`:

```toml
# dns_cache_interval_secs = 300   # DNS cache harvest (confusable-domain detection)
```

Run: `cargo test -p ion-drift-web` — the config-docs test enforces example/struct agreement; it must pass with the pair added together.

- [ ] **Step 3: Write the poller** — `tasks/dns_cache.rs`:

```rust
//! DNS cache poller — harvests every name the router resolves and runs the
//! confusable-domain skeleton match over it.
//!
//! Only sees devices that use the router as their resolver; the DNS deviation
//! detector already identifies the ones that do not. Observations are the
//! name→IP join key (dns.db), retained on the windowed count + prune model.

use std::time::Duration;

use mikrotik_core::resources::ip::DnsCacheEntry;

use crate::confusable::detector::{build_finding, WatchIndex, CONFUSABLE_MODULE};
use crate::confusable::skeleton::{normalize_domain, skeleton_of};
use crate::router_queue::{Priority, QueuedRequest};
use crate::state::AppState;
use crate::task_supervisor::TaskSupervisor;

const POLLER_ID: &str = "dns-cache";
/// Stagger past startup, same rationale as the advisory evaluator.
const STARTUP_DELAY_SECS: u64 = 120;
/// Observation retention: long enough that "first seen" is meaningful for
/// investigation, pruned so the table cannot grow without bound.
const OBSERVATION_RETENTION_SECS: i64 = 90 * 86400;

pub fn spawn_dns_cache_poller(supervisor: &TaskSupervisor, state: AppState) {
    let interval_secs = state.config.polling.dns_cache_interval_secs;
    supervisor.spawn("dns-cache-poller", move || {
        let state = state.clone();
        Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(STARTUP_DELAY_SECS)).await;
            tracing::info!(interval_secs, "dns cache poller starting");
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                if let Err(e) = poll_once(&state).await {
                    tracing::warn!(error = %e, "dns-cache: cycle failed");
                }
            }
        })
    });
}

async fn poll_once(state: &AppState) -> Result<(), String> {
    let results = state
        .router_queue
        .submit(POLLER_ID, Priority::Low, vec![QueuedRequest::get("ip/dns/cache")])
        .await
        .map_err(|e| format!("dns cache fetch failed: {e}"))?;
    let entries: Vec<DnsCacheEntry> = match results.first() {
        Some(Ok(v)) => serde_json::from_value(v.clone())
            .map_err(|e| format!("dns cache deserialize: {e}"))?,
        Some(Err(e)) => return Err(format!("dns cache fetch failed: {e}")),
        None => return Err("dns cache fetch returned no result".to_string()),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // One observation per name; addresses aggregated across its A/AAAA/CNAME
    // rows in this snapshot.
    let mut by_name: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for e in &entries {
        let name = normalize_domain(&e.name);
        if name.is_empty() {
            continue;
        }
        let addrs = by_name.entry(name).or_default();
        if let Some(data) = &e.data {
            addrs.push(data.clone());
        }
    }

    let index = WatchIndex::build(&state.dns_store.list_watchlist().await?);

    for (name, addresses) in &by_name {
        state
            .dns_store
            .upsert_observation(name, &skeleton_of(name), addresses, now)
            .await?;
        // Match every cycle, not only on new names: upsert_finding dedups on
        // (module, finding_id), and re-matching lets a watchlist update catch
        // names still present in the cache.
        if let Some(hit) = index.match_name(name) {
            let finding = build_finding(&hit, addresses, now);
            if let Err(e) = state
                .findings_store
                .upsert_finding(CONFUSABLE_MODULE, &finding, None, None)
                .await
            {
                tracing::warn!(error = %e, name = %name, "dns-cache: finding upsert failed");
            } else {
                tracing::warn!(
                    observed = %hit.observed,
                    resembles = %hit.watchlist_domain,
                    "confusable domain observed"
                );
            }
        }
    }

    match state.dns_store.prune_observations(now - OBSERVATION_RETENTION_SECS).await {
        Ok(0) => {}
        Ok(n) => tracing::debug!(count = n, "dns-cache: pruned stale observations"),
        Err(e) => tracing::warn!(error = %e, "dns-cache: prune failed"),
    }
    Ok(())
}
```

(Adapt the exact `upsert_finding` signature/await-ness and `TaskSupervisor::spawn` closure shape to what `tasks/advisory.rs` compiles with today — copy that file's idiom verbatim.)

- [ ] **Step 4: Wire startup** —
  - `state.rs`: add `pub dns_store: std::sync::Arc<ion_drift_storage::dns::DnsStore>,` to `AppState` (next to `advisory_store` at the `main.rs:960` construction site).
  - `main.rs`: init after the advisory store block:

```rust
    let dns_store = Arc::new(
        ion_drift_storage::dns::DnsStore::new(&data_dir.join("dns.db"))
            .await
            .map_err(|e| anyhow::anyhow!("failed to init dns store: {e}"))?,
    );
```

  - `main.rs`: load the watchlist right after the advisory catalog block, with the same three-way log match (degraded → warn with rejects; zero entries → warn naming both dirs and `DRIFT_CONFUSABLE_SEED_DIR`; ok → info). Overlay dir: `data_dir.join("confusable")`. Seed dir helper `confusable_seed_dir()` is a copy of `advisory_seed_dir()` (`main.rs:1087`) with `advisories`→`confusable` and the env var renamed.
  - `tasks/mod.rs`: add `mod dns_cache;` and, next to the advisory evaluator spawn: `dns_cache::spawn_dns_cache_poller(&state.task_supervisor, state.clone());`

- [ ] **Step 5: Full verification**

Run: `cargo test --workspace`
Expected: all green (all prior tasks' tests + untouched baseline).

Run: `cargo deny check`
Expected: ok.

Boot check (loopback, throwaway data dir — same harness the 2026-08-04 audit used): startup log shows `dns cache poller starting` and a `confusable watchlist loaded`-class line with `entries_loaded ≥ 15`. **Delete the throwaway data dir afterwards** (it contains a generated KEK — cp100's leftover is the cautionary tale).

- [ ] **Step 6: Commit**

```bash
git add crates/ion-drift-web/src/tasks/dns_cache.rs crates/ion-drift-web/src/tasks/mod.rs \
        crates/ion-drift-web/src/state.rs crates/ion-drift-web/src/main.rs \
        crates/ion-drift-web/src/modules_registry/service.rs \
        crates/ion-drift-web/src/config.rs config/server.example.toml
git commit -m "feat(confusable): dns-cache poller wired end-to-end"
```

---

## Out of Scope (explicitly deferred — do not build here)

- **GitHub feed refresh** (watchlist tier 2). No updater exists for the advisory catalog either; when built, build it ONCE, generically, serving both catalogs. Until then: bundled seed + operator overlay only.
- Hostname join into Sankey/Investigation/World Map (the `dns_observation` table is deliberately shaped to enable it later via `observations_since`).
- Confusable flagging of hostnames Drift itself renders (separate small defensive fix, worth doing regardless — noted in the parked doc).
- Label-window scanning for brand-embedding (`paypal.com.evil.com`).
- Any UI beyond the standard findings surfaces.

## Self-Review Notes

- Spec coverage vs the parked design doc: skeleton-not-Cyrillic ✔ (Task 3 doc comment + tests), three-tier watchlist → tiers 1+3 shipped, tier 2 explicitly deferred ✔, core-not-module decision ✔ (sidesteps `cx.connection() = None`), DNS-name source prerequisite ✔ (Task 1 + 6), catalog discipline reuse ✔ (Task 4), "reuse the loader discipline, not the schema" ✔ (watchlist schema is its own, remote-domain shaped).
- Type consistency: `WatchlistEntry` fields identical across Tasks 2/4/5; `upsert_observation(name, skeleton, addresses, now) -> bool` used identically in Tasks 2 and 6; `CONFUSABLE_MODULE` defined Task 5, consumed Task 6.
- Two deliberate judgment calls, both cheap to reverse: match-every-cycle (vs new-names-only) so watchlist updates catch cached names — cost is one BTreeMap lookup per cached name per 5 min; 90-day observation retention (vs advisory's 30) because first-seen dates are investigation evidence, not detection state.
