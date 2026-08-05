//! DNS store — persistence for observed DNS names and the confusable-domain
//! watchlist.
//!
//! `dns_observation` is the name→IP join key: one row per distinct name the
//! router's DNS cache has been seen resolving, with first/last-seen window.
//! Sole writer: the DNS cache poller (`tasks/dns_cache.rs`). Follows the
//! windowed counting + prune model — absence of a row is the zero.
//!
//! `confusable_watchlist` holds brands worth impersonating, keyed by domain
//! with a precomputed UTS #39 skeleton. Watchlist content is **third-party
//! data loaded from a JSON catalog**, never a Rust literal; all writes bind
//! parameters. Merge semantics mirror the advisory catalog: higher
//! `catalog_version` wins, a tie goes to the later write, so an operator
//! overlay layers over a bundled seed of the same version.

use std::path::Path;
use std::sync::Arc;

use rusqlite::{Connection, Row, params};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// One observed DNS name: the router's cache has been seen resolving it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsObservation {
    pub name: String,
    /// UTS #39 skeleton of `name`, precomputed by the writer so matching and
    /// storage can never disagree about the canonical form.
    pub skeleton: String,
    /// Resolved payloads seen in the latest sighting (IPs, CNAME targets).
    pub addresses: Vec<String>,
    pub first_seen: i64,
    pub last_seen: i64,
}

/// One watchlist row: a brand-owned domain whose skeleton observed names are
/// compared against. `allow: true` marks a known-good lookalike whose
/// collision must be suppressed rather than reported.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchlistEntry {
    pub domain: String,
    pub brand: String,
    pub skeleton: String,
    pub allow: bool,
    pub source: String,
    pub catalog_version: i64,
}

pub struct DnsStore {
    db: Arc<Mutex<Connection>>,
}

impl DnsStore {
    /// Schema version stamped into `PRAGMA user_version` for `dns.db`.
    /// v1 = the baseline; v2 adds CHECK constraints bounding every field an
    /// attacker can influence. Bump when appending a step to
    /// [`Self::MIGRATION_STEPS`].
    pub const SCHEMA_VERSION: u32 = 2;

    /// Versioned migrations applied after the v1 baseline, in ascending order.
    ///
    /// v2 — CHECK constraints as the backstop under the code-level staging
    /// layer (`ion_drift_web::staging`). The staging functions are where a bad
    /// value is supposed to be caught; these constraints are what catches a
    /// future writer that forgets to call them. SQLite cannot add a CHECK with
    /// `ALTER TABLE`, so each table is rebuilt.
    ///
    /// Rows are **repaired, never dropped**: over-long values are truncated to
    /// the bound and out-of-range numbers are clamped, the same "bound, don't
    /// drop" rule the staging layer follows. A migration step is a static SQL
    /// string and cannot log a dropped-row count, so dropping would mean
    /// silent data loss — unacceptable for evidence an operator may be
    /// mid-investigation on. The single exception is an observation whose name
    /// is empty, which cannot be repaired into something matchable; the writer
    /// has always skipped empty names, so this is a theoretical row.
    ///
    /// `INSERT OR IGNORE` because truncating two names that differ only past
    /// character 253 collapses them onto one primary key.
    const MIGRATION_STEPS: &'static [(u32, &'static str)] = &[(
        2,
        "
        CREATE TABLE dns_observation_new (
            name TEXT PRIMARY KEY
                CHECK (length(name) BETWEEN 1 AND 253),
            skeleton TEXT NOT NULL
                CHECK (length(skeleton) <= 253),
            addresses TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL
                CHECK (last_seen >= first_seen)
        );

        INSERT OR IGNORE INTO dns_observation_new
            (name, skeleton, addresses, first_seen, last_seen)
        SELECT substr(name, 1, 253),
               substr(skeleton, 1, 253),
               addresses,
               first_seen,
               max(last_seen, first_seen)
        FROM dns_observation
        WHERE length(trim(name)) > 0;

        DROP TABLE dns_observation;
        ALTER TABLE dns_observation_new RENAME TO dns_observation;

        CREATE INDEX idx_dns_observation_skeleton ON dns_observation(skeleton);
        CREATE INDEX idx_dns_observation_last_seen ON dns_observation(last_seen);

        CREATE TABLE confusable_watchlist_new (
            domain TEXT PRIMARY KEY
                CHECK (length(domain) BETWEEN 1 AND 253),
            brand TEXT NOT NULL
                CHECK (length(brand) <= 128),
            skeleton TEXT NOT NULL
                CHECK (length(skeleton) <= 253),
            allow INTEGER NOT NULL DEFAULT 0
                CHECK (allow IN (0, 1)),
            source TEXT NOT NULL,
            catalog_version INTEGER NOT NULL
                CHECK (catalog_version >= 0)
        );

        INSERT OR IGNORE INTO confusable_watchlist_new
            (domain, brand, skeleton, allow, source, catalog_version)
        SELECT substr(domain, 1, 253),
               substr(brand, 1, 128),
               substr(skeleton, 1, 253),
               CASE WHEN allow = 0 THEN 0 ELSE 1 END,
               source,
               max(catalog_version, 0)
        FROM confusable_watchlist
        WHERE length(trim(domain)) > 0;

        DROP TABLE confusable_watchlist;
        ALTER TABLE confusable_watchlist_new RENAME TO confusable_watchlist;

        CREATE INDEX idx_confusable_watchlist_skeleton
            ON confusable_watchlist(skeleton);
        ",
    )];

    pub async fn new(db_path: &Path) -> Result<Self, String> {
        let mut conn =
            Connection::open(db_path).map_err(|e| format!("failed to open dns db: {e}"))?;
        let db_version = crate::migrations::open_guard(&conn, "dns.db", Self::SCHEMA_VERSION)?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| format!("pragma failed: {e}"))?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS dns_observation (
                name TEXT PRIMARY KEY,
                skeleton TEXT NOT NULL,
                addresses TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_dns_observation_skeleton
                ON dns_observation(skeleton);
            CREATE INDEX IF NOT EXISTS idx_dns_observation_last_seen
                ON dns_observation(last_seen);

            CREATE TABLE IF NOT EXISTS confusable_watchlist (
                domain TEXT PRIMARY KEY,
                brand TEXT NOT NULL,
                skeleton TEXT NOT NULL,
                allow INTEGER NOT NULL DEFAULT 0,
                source TEXT NOT NULL,
                catalog_version INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_confusable_watchlist_skeleton
                ON confusable_watchlist(skeleton);
            ",
        )
        .map_err(|e| format!("schema creation failed: {e}"))?;

        crate::migrations::apply_versioned(&mut conn, "dns.db", db_version, Self::MIGRATION_STEPS)?;
        crate::migrations::stamp(&conn, "dns.db", Self::SCHEMA_VERSION)?;

        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
        })
    }

    /// Record a sighting of `name`. Returns `true` when the name is new; a
    /// repeat sighting refreshes `last_seen`, `addresses` and `skeleton` in
    /// place, keeping `first_seen`.
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

    /// Observations last seen at or after `cutoff`, newest first.
    pub async fn observations_since(&self, cutoff: i64) -> Result<Vec<DnsObservation>, String> {
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT name, skeleton, addresses, first_seen, last_seen
                 FROM dns_observation
                 WHERE last_seen >= ?1
                 ORDER BY last_seen DESC",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map(params![cutoff], Self::map_observation)
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))
    }

    /// Drop observations whose latest sighting is older than `cutoff` (an
    /// absolute unix timestamp, not an age). Returns rows deleted.
    pub async fn prune_observations(&self, cutoff: i64) -> Result<usize, String> {
        let db = self.db.lock().await;
        db.execute(
            "DELETE FROM dns_observation WHERE last_seen < ?1",
            params![cutoff],
        )
        .map_err(|e| format!("prune_observations failed: {e}"))
    }

    /// Insert a watchlist row, or refine the existing row keyed by `domain`.
    /// A higher `catalog_version` wins; the same version overwrites, so the
    /// operator overlay (loaded second) layers over the bundled seed.
    pub async fn upsert_watchlist_entry(&self, e: &WatchlistEntry) -> Result<(), String> {
        let db = self.db.lock().await;
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
            params![
                e.domain,
                e.brand,
                e.skeleton,
                e.allow as i64,
                e.source,
                e.catalog_version
            ],
        )
        .map_err(|e| format!("upsert_watchlist_entry failed: {e}"))?;
        Ok(())
    }

    pub async fn list_watchlist(&self) -> Result<Vec<WatchlistEntry>, String> {
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT domain, brand, skeleton, allow, source, catalog_version
                 FROM confusable_watchlist ORDER BY domain",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map([], Self::map_watchlist_entry)
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))
    }

    fn map_observation(row: &Row<'_>) -> rusqlite::Result<DnsObservation> {
        let addresses_json: String = row.get(2)?;

        Ok(DnsObservation {
            name: row.get(0)?,
            skeleton: row.get(1)?,
            addresses: serde_json::from_str(&addresses_json).unwrap_or_default(),
            first_seen: row.get(3)?,
            last_seen: row.get(4)?,
        })
    }

    fn map_watchlist_entry(row: &Row<'_>) -> rusqlite::Result<WatchlistEntry> {
        let allow: i64 = row.get(3)?;

        Ok(WatchlistEntry {
            domain: row.get(0)?,
            brand: row.get(1)?,
            skeleton: row.get(2)?,
            allow: allow != 0,
            source: row.get(4)?,
            catalog_version: row.get(5)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    /// Build a dns.db exactly as a v1 binary left it: the v1 baseline DDL
    /// (no CHECK constraints), `user_version = 1`, and rows that the v2
    /// constraints would reject unrepaired. Copied verbatim rather than
    /// calling current code, so this fixture stays a v1 database even after
    /// the baseline moves on.
    fn create_v1_dns_database(path: &Path) {
        let conn = Connection::open(path).expect("create v1 dns db");
        conn.execute_batch(
            "
            CREATE TABLE dns_observation (
                name TEXT PRIMARY KEY,
                skeleton TEXT NOT NULL,
                addresses TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            );
            CREATE INDEX idx_dns_observation_skeleton ON dns_observation(skeleton);
            CREATE INDEX idx_dns_observation_last_seen ON dns_observation(last_seen);

            CREATE TABLE confusable_watchlist (
                domain TEXT PRIMARY KEY,
                brand TEXT NOT NULL,
                skeleton TEXT NOT NULL,
                allow INTEGER NOT NULL DEFAULT 0,
                source TEXT NOT NULL,
                catalog_version INTEGER NOT NULL
            );
            CREATE INDEX idx_confusable_watchlist_skeleton
                ON confusable_watchlist(skeleton);

            PRAGMA user_version = 1;
            ",
        )
        .expect("v1 dns fixture ddl");

        let long_name = "a".repeat(400);
        let long_brand = "B".repeat(400);
        conn.execute(
            "INSERT INTO dns_observation (name, skeleton, addresses, first_seen, last_seen)
             VALUES ('good.example', 'good.example', '[\"10.0.0.1\"]', 100, 200)",
            [],
        )
        .expect("good observation");
        conn.execute(
            "INSERT INTO dns_observation (name, skeleton, addresses, first_seen, last_seen)
             VALUES (?1, ?1, '[]', 100, 50)",
            params![long_name],
        )
        .expect("oversized observation with last_seen before first_seen");
        conn.execute(
            "INSERT INTO confusable_watchlist
                (domain, brand, skeleton, allow, source, catalog_version)
             VALUES ('paypal.com', ?1, 'paypal.com', 7, 'bundled', -3)",
            params![long_brand],
        )
        .expect("watchlist row with oversized brand, odd allow, negative version");
    }

    fn user_version(path: &Path) -> i64 {
        let conn = Connection::open(path).expect("open for version check");
        conn.query_row("PRAGMA user_version", [], |r| r.get(0))
            .expect("user_version")
    }

    #[tokio::test]
    async fn v1_database_upgrades_to_v2_repairing_rows_instead_of_dropping_them() {
        let f = NamedTempFile::new().unwrap();
        create_v1_dns_database(f.path());
        assert_eq!(user_version(f.path()), 1, "fixture must start at v1");

        let store = DnsStore::new(f.path()).await.expect("v1 dns db must open");
        assert_eq!(user_version(f.path()), 2, "v1 database migrates to v2");

        // Nothing was dropped: both observations survive, the oversized one
        // truncated to the bound rather than deleted.
        let obs = store.observations_since(0).await.unwrap();
        assert_eq!(obs.len(), 2, "no observation was dropped by the migration");
        let long = obs
            .iter()
            .find(|o| o.name.starts_with("aaa"))
            .expect("the oversized row survived");
        assert_eq!(long.name.len(), 253, "over-long name truncated to the bound");
        assert!(
            long.last_seen >= long.first_seen,
            "last_seen repaired to satisfy the ordering constraint"
        );

        let list = store.list_watchlist().await.unwrap();
        assert_eq!(list.len(), 1, "no watchlist row was dropped");
        assert_eq!(list[0].brand.len(), 128, "over-long brand truncated");
        assert!(list[0].allow, "non-boolean allow repaired to true");
        assert_eq!(list[0].catalog_version, 0, "negative version clamped to zero");
    }

    #[tokio::test]
    async fn migrated_dns_database_reopens_without_rerunning_steps() {
        let f = NamedTempFile::new().unwrap();
        create_v1_dns_database(f.path());

        drop(DnsStore::new(f.path()).await.expect("migrating open"));
        assert_eq!(user_version(f.path()), 2);

        // The v2 step uses plain CREATE TABLE, so a wrongly re-run step fails
        // loudly here instead of passing silently.
        drop(DnsStore::new(f.path()).await.expect("reopen at v2"));
        assert_eq!(user_version(f.path()), 2);
    }

    #[tokio::test]
    async fn fresh_database_lands_on_v2_with_constraints_enforced() {
        let f = NamedTempFile::new().unwrap();
        let store = DnsStore::new(f.path()).await.unwrap();
        assert_eq!(user_version(f.path()), 2, "fresh database lands on v2");

        // The backstop is real: a writer bypassing the staging layer is
        // rejected by the database itself, not merely by convention.
        let err = store
            .upsert_observation(&"x".repeat(400), "x", &[], 100)
            .await
            .expect_err("CHECK must reject an over-long name");
        assert!(err.contains("insert failed"), "got: {err}");
    }

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
        assert_eq!(
            rows[0].addresses,
            vec!["203.0.113.10"],
            "addresses follow the latest sighting"
        );
    }

    #[tokio::test]
    async fn prune_observations_deletes_only_stale_names() {
        let f = NamedTempFile::new().unwrap();
        let store = DnsStore::new(f.path()).await.unwrap();
        store
            .upsert_observation("old.example", "old.example", &[], 100)
            .await
            .unwrap();
        store
            .upsert_observation("new.example", "new.example", &[], 300)
            .await
            .unwrap();

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

        store
            .upsert_watchlist_entry(&mk("PayPal v2", 2, "bundled"))
            .await
            .unwrap();
        store
            .upsert_watchlist_entry(&mk("stale v1", 1, "operator"))
            .await
            .unwrap();
        let list = store.list_watchlist().await.unwrap();
        assert_eq!(list[0].brand, "PayPal v2", "lower version must not clobber");

        store
            .upsert_watchlist_entry(&mk("operator v2", 2, "operator"))
            .await
            .unwrap();
        let list = store.list_watchlist().await.unwrap();
        assert_eq!(
            list[0].brand, "operator v2",
            "same version: later write (operator overlay) wins"
        );
    }
}
