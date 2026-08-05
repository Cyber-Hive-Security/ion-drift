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
    /// Bump when appending a step to [`Self::MIGRATION_STEPS`].
    pub const SCHEMA_VERSION: u32 = 1;

    /// Versioned migrations applied after the v1 baseline. None yet.
    const MIGRATION_STEPS: &'static [(u32, &'static str)] = &[];

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
