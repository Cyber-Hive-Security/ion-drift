//! Advisory store — persistence for the advisory catalog and the attack
//! observations that corroborate it.
//!
//! An advisory describes a condition worth telling the operator about: which
//! surface class it applies to, which states make it relevant, and which
//! versions (if any) fix it. Advisory content is **third-party data loaded
//! from a JSON catalog**, never a Rust literal — core carries no identifiers
//! of its own. The catalog-to-detector linkage lives in `advisory_signal`
//! rows, so core stays module-agnostic.
//!
//! Because every value here originates in an untrusted file, all writes bind
//! parameters; nothing is interpolated into SQL.
//!
//! Dedup keys: `advisory_id` for advisories, `(advisory_id, signal_id)` for
//! signal links. Re-running the catalog loader refines rows in place rather
//! than duplicating them.

use std::path::Path;
use std::sync::Arc;

use rusqlite::{Connection, Row, params};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// One catalog advisory as stored in `advisory.db`.
///
/// The `Vec<String>` fields and `version_constraint` are persisted as JSON
/// text columns — SQLite has no array type and the shapes are read whole.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdvisoryRecord {
    pub advisory_id: String,
    pub title: String,
    pub narrative: String,
    pub severity: String,
    pub requires_surface_class: String,
    pub requires_surface_names: Vec<String>,
    pub requires_state: Vec<String>,
    /// JSON constraint expression. `None` matches any version.
    pub version_constraint: Option<String>,
    pub no_fixed_release: bool,
    pub fixed_versions: Vec<String>,
    pub mitigations: Vec<String>,
    pub references: Vec<String>,
    pub attack_techniques: Vec<String>,
    /// Provenance: `"bundled"` (seed) or `"operator"` (data-dir overlay).
    pub source: String,
    pub catalog_version: i64,
    pub generated_at: String,
}

/// A single observed occurrence of a signal against one surface.
///
/// Observations are raw corroboration, not conclusions — the exploitation
/// evaluator windows them and decides what, if anything, to surface.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttackObservation {
    pub id: i64,
    pub device_id: String,
    pub surface_key: String,
    pub signal_id: String,
    pub src_ips: Vec<String>,
    pub event_count: i64,
    pub observed_at: i64,
}

/// One accumulator row: the deduped login-failure count one evaluator cycle
/// observed on one surface. Raw per-cycle state, not a conclusion — Phase 4's
/// cross-cycle counting windows these rows and decides what to surface.
/// Sole writer: the advisory evaluator (see `tasks/advisory.rs`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthFailure {
    pub id: i64,
    pub device_id: String,
    pub surface_key: String,
    pub failure_count: i64,
    pub src_ips: Vec<String>,
    pub observed_at: i64,
}

pub struct AdvisoryStore {
    db: Arc<Mutex<Connection>>,
}

impl AdvisoryStore {
    /// Schema version stamped into `PRAGMA user_version` for `advisory.db`.
    /// v1 = the Phase 1 baseline; v2 adds `advisory_auth_failure`, the
    /// cross-cycle auth-failure accumulator. Bump when appending a step to
    /// [`Self::MIGRATION_STEPS`] (see `crate::migrations`).
    pub const SCHEMA_VERSION: u32 = 2;

    /// Versioned migrations applied after the v1 baseline, in ascending
    /// order. Steps use plain `CREATE TABLE` (no `IF NOT EXISTS`) on
    /// purpose: `apply_versioned` guarantees run-once, and a wrongly re-run
    /// step must fail loudly rather than pass as a no-op.
    ///
    /// v2 — `advisory_auth_failure`: one row per evaluator cycle per surface
    /// carrying the deduped login-failure count for that cycle. This is the
    /// persisted state cross-cycle counting (Phase 4, wired — see
    /// `advisory/sustained.rs`) reads; the advisory evaluator is its sole
    /// writer (Phase 3, wired — see `tasks/advisory.rs` and
    /// `exploitation::note_auth_failures`). Same windowed counting +
    /// prune model as `advisory_attack_observation`.
    const MIGRATION_STEPS: &'static [(u32, &'static str)] = &[(
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
    )];

    pub async fn new(db_path: &Path) -> Result<Self, String> {
        let mut conn =
            Connection::open(db_path).map_err(|e| format!("failed to open advisory db: {e}"))?;
        let db_version =
            crate::migrations::open_guard(&conn, "advisory.db", Self::SCHEMA_VERSION)?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| format!("pragma failed: {e}"))?;

        // `references` is a SQLite keyword, hence the `_json` suffix on that
        // column. The other JSON columns keep their contract field names.
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS advisory (
                advisory_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                narrative TEXT NOT NULL,
                severity TEXT NOT NULL,
                requires_surface_class TEXT NOT NULL,
                requires_surface_names TEXT NOT NULL,
                requires_state TEXT NOT NULL,
                version_constraint TEXT,
                no_fixed_release INTEGER NOT NULL DEFAULT 0,
                fixed_versions TEXT NOT NULL,
                mitigations TEXT NOT NULL,
                references_json TEXT NOT NULL,
                attack_techniques TEXT NOT NULL,
                source TEXT NOT NULL,
                catalog_version INTEGER NOT NULL,
                generated_at TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS advisory_signal (
                advisory_id TEXT NOT NULL,
                signal_id TEXT NOT NULL,
                confidence TEXT NOT NULL
                    CHECK (confidence IN ('strong', 'corroborating')),
                description TEXT NOT NULL,
                PRIMARY KEY (advisory_id, signal_id)
            );

            CREATE INDEX IF NOT EXISTS idx_advisory_signal_signal
                ON advisory_signal(signal_id);

            CREATE TABLE IF NOT EXISTS advisory_attack_observation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                surface_key TEXT NOT NULL,
                signal_id TEXT NOT NULL,
                src_ips TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                observed_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_advisory_obs_surface
                ON advisory_attack_observation(surface_key, observed_at DESC);

            CREATE TABLE IF NOT EXISTS advisory_suppression (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                advisory_id TEXT NOT NULL,
                surface_key TEXT NOT NULL,
                reason TEXT,
                created_by TEXT,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                UNIQUE(advisory_id, surface_key)
            );
            ",
        )
        .map_err(|e| format!("schema creation failed: {e}"))?;

        crate::migrations::apply_versioned(
            &mut conn,
            "advisory.db",
            db_version,
            Self::MIGRATION_STEPS,
        )?;

        crate::migrations::stamp(&conn, "advisory.db", Self::SCHEMA_VERSION)?;

        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
        })
    }

    /// Insert a catalog advisory, or refine the existing row keyed by
    /// `advisory_id`. The loader calls this once per entry per load, so the
    /// operator overlay overwrites the bundled seed on merge.
    pub async fn upsert_advisory(&self, a: &AdvisoryRecord) -> Result<(), String> {
        let requires_surface_names = serde_json::to_string(&a.requires_surface_names)
            .map_err(|e| format!("serialize requires_surface_names: {e}"))?;
        let requires_state = serde_json::to_string(&a.requires_state)
            .map_err(|e| format!("serialize requires_state: {e}"))?;
        let fixed_versions = serde_json::to_string(&a.fixed_versions)
            .map_err(|e| format!("serialize fixed_versions: {e}"))?;
        let mitigations = serde_json::to_string(&a.mitigations)
            .map_err(|e| format!("serialize mitigations: {e}"))?;
        let references = serde_json::to_string(&a.references)
            .map_err(|e| format!("serialize references: {e}"))?;
        let attack_techniques = serde_json::to_string(&a.attack_techniques)
            .map_err(|e| format!("serialize attack_techniques: {e}"))?;

        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO advisory
                (advisory_id, title, narrative, severity, requires_surface_class,
                 requires_surface_names, requires_state, version_constraint,
                 no_fixed_release, fixed_versions, mitigations, references_json,
                 attack_techniques, source, catalog_version, generated_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             ON CONFLICT(advisory_id) DO UPDATE SET
                title = excluded.title,
                narrative = excluded.narrative,
                severity = excluded.severity,
                requires_surface_class = excluded.requires_surface_class,
                requires_surface_names = excluded.requires_surface_names,
                requires_state = excluded.requires_state,
                version_constraint = excluded.version_constraint,
                no_fixed_release = excluded.no_fixed_release,
                fixed_versions = excluded.fixed_versions,
                mitigations = excluded.mitigations,
                references_json = excluded.references_json,
                attack_techniques = excluded.attack_techniques,
                source = excluded.source,
                catalog_version = excluded.catalog_version,
                generated_at = excluded.generated_at,
                updated_at = excluded.updated_at",
            params![
                a.advisory_id,
                a.title,
                a.narrative,
                a.severity,
                a.requires_surface_class,
                requires_surface_names,
                requires_state,
                a.version_constraint,
                a.no_fixed_release,
                fixed_versions,
                mitigations,
                references,
                attack_techniques,
                a.source,
                a.catalog_version,
                a.generated_at,
                now_unix(),
            ],
        )
        .map_err(|e| format!("upsert_advisory failed: {e}"))?;
        Ok(())
    }

    /// Link a signal to an advisory. `confidence` must be `strong` or
    /// `corroborating` — the column CHECK rejects anything else, so a
    /// malformed catalog entry fails here instead of silently widening
    /// what counts as evidence.
    pub async fn upsert_signal(
        &self,
        advisory_id: &str,
        signal_id: &str,
        confidence: &str,
        description: &str,
    ) -> Result<(), String> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO advisory_signal
                (advisory_id, signal_id, confidence, description)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(advisory_id, signal_id) DO UPDATE SET
                confidence = excluded.confidence,
                description = excluded.description",
            params![advisory_id, signal_id, confidence, description],
        )
        .map_err(|e| format!("upsert_signal failed: {e}"))?;
        Ok(())
    }

    pub async fn record_observation(
        &self,
        device_id: &str,
        surface_key: &str,
        signal_id: &str,
        src_ips: &[String],
        event_count: i64,
        observed_at: i64,
    ) -> Result<(), String> {
        let src_ips_json =
            serde_json::to_string(src_ips).map_err(|e| format!("serialize src_ips: {e}"))?;

        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO advisory_attack_observation
                (device_id, surface_key, signal_id, src_ips, event_count, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                device_id,
                surface_key,
                signal_id,
                src_ips_json,
                event_count,
                observed_at
            ],
        )
        .map_err(|e| format!("record_observation failed: {e}"))?;
        Ok(())
    }

    /// Observations at or after `cutoff`, newest first. This is the window
    /// the exploitation evaluator reasons over.
    pub async fn observations_since(&self, cutoff: i64) -> Result<Vec<AttackObservation>, String> {
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT id, device_id, surface_key, signal_id, src_ips,
                        event_count, observed_at
                 FROM advisory_attack_observation
                 WHERE observed_at >= ?1
                 ORDER BY observed_at DESC",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map(params![cutoff], Self::map_observation)
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))
    }

    /// Advisories a signal is evidence for, as `(advisory_id, confidence)`.
    pub async fn advisories_for_signal(
        &self,
        signal_id: &str,
    ) -> Result<Vec<(String, String)>, String> {
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT advisory_id, confidence
                 FROM advisory_signal
                 WHERE signal_id = ?1
                 ORDER BY advisory_id",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map(params![signal_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))
    }

    /// Drop observations older than `cutoff` (an absolute unix timestamp,
    /// not an age). Returns the number of rows deleted.
    pub async fn prune_observations(&self, cutoff: i64) -> Result<usize, String> {
        let db = self.db.lock().await;
        db.execute(
            "DELETE FROM advisory_attack_observation WHERE observed_at < ?1",
            params![cutoff],
        )
        .map_err(|e| format!("prune_observations failed: {e}"))
    }

    /// Record one evaluator cycle's deduped login-failure count for one
    /// surface. Same windowed counting + prune model as
    /// [`Self::record_observation`]; absence of a row is the zero.
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
            params![
                device_id,
                surface_key,
                failure_count,
                src_ips_json,
                observed_at
            ],
        )
        .map_err(|e| format!("record_auth_failure failed: {e}"))?;
        Ok(())
    }

    /// Accumulator rows at or after `cutoff`, newest first. This is the
    /// window cross-cycle counting (Phase 4) reasons over.
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

    /// Drop accumulator rows older than `cutoff` (an absolute unix timestamp,
    /// not an age). Returns the number of rows deleted.
    pub async fn prune_auth_failures(&self, cutoff: i64) -> Result<usize, String> {
        let db = self.db.lock().await;
        db.execute(
            "DELETE FROM advisory_auth_failure WHERE observed_at < ?1",
            params![cutoff],
        )
        .map_err(|e| format!("prune_auth_failures failed: {e}"))
    }

    pub async fn list_advisories(&self) -> Result<Vec<AdvisoryRecord>, String> {
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT advisory_id, title, narrative, severity, requires_surface_class,
                        requires_surface_names, requires_state, version_constraint,
                        no_fixed_release, fixed_versions, mitigations, references_json,
                        attack_techniques, source, catalog_version, generated_at
                 FROM advisory ORDER BY advisory_id",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map([], Self::map_advisory)
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))
    }

    /// JSON columns decode lossily: a row written by a newer schema (or hand
    /// edited) degrades to an empty list rather than failing the whole read.
    ///
    /// That makes an empty `requires_surface_names` reachable without any
    /// catalog change, so consumers must read an empty scope list as "matches
    /// nothing" rather than "matches everything" — a corrupt column must not be
    /// able to widen an advisory onto surfaces it was never written for. See
    /// `advisory::exploitation::advisory_covers_surface`, which fails closed.
    fn map_advisory(row: &Row<'_>) -> rusqlite::Result<AdvisoryRecord> {
        let requires_surface_names_json: String = row.get(5)?;
        let requires_state_json: String = row.get(6)?;
        let fixed_versions_json: String = row.get(9)?;
        let mitigations_json: String = row.get(10)?;
        let references_json: String = row.get(11)?;
        let attack_techniques_json: String = row.get(12)?;

        Ok(AdvisoryRecord {
            advisory_id: row.get(0)?,
            title: row.get(1)?,
            narrative: row.get(2)?,
            severity: row.get(3)?,
            requires_surface_class: row.get(4)?,
            requires_surface_names: serde_json::from_str(&requires_surface_names_json)
                .unwrap_or_default(),
            requires_state: serde_json::from_str(&requires_state_json).unwrap_or_default(),
            version_constraint: row.get(7)?,
            no_fixed_release: row.get(8)?,
            fixed_versions: serde_json::from_str(&fixed_versions_json).unwrap_or_default(),
            mitigations: serde_json::from_str(&mitigations_json).unwrap_or_default(),
            references: serde_json::from_str(&references_json).unwrap_or_default(),
            attack_techniques: serde_json::from_str(&attack_techniques_json).unwrap_or_default(),
            source: row.get(13)?,
            catalog_version: row.get(14)?,
            generated_at: row.get(15)?,
        })
    }

    fn map_observation(row: &Row<'_>) -> rusqlite::Result<AttackObservation> {
        let src_ips_json: String = row.get(4)?;

        Ok(AttackObservation {
            id: row.get(0)?,
            device_id: row.get(1)?,
            surface_key: row.get(2)?,
            signal_id: row.get(3)?,
            src_ips: serde_json::from_str(&src_ips_json).unwrap_or_default(),
            event_count: row.get(5)?,
            observed_at: row.get(6)?,
        })
    }

    fn map_auth_failure(row: &Row<'_>) -> rusqlite::Result<AuthFailure> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn sample(id: &str, catalog_version: i64) -> AdvisoryRecord {
        AdvisoryRecord {
            advisory_id: id.to_string(),
            title: "title".into(),
            narrative: "narrative".into(),
            severity: "high".into(),
            requires_surface_class: "service".into(),
            requires_surface_names: vec!["api".into(), "api-ssl".into()],
            requires_state: vec!["exposed".into()],
            version_constraint: None,
            no_fixed_release: true,
            fixed_versions: vec![],
            mitigations: vec!["restrict the service".into()],
            references: vec!["https://example.invalid/adv".into()],
            attack_techniques: vec!["T1110".into()],
            source: "bundled".into(),
            catalog_version,
            generated_at: "2026-07-28".into(),
        }
    }

    #[tokio::test]
    async fn fresh_db_stamps_schema_version() {
        let f = NamedTempFile::new().unwrap();
        let _store = AdvisoryStore::new(f.path()).await.unwrap();

        let conn = Connection::open(f.path()).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, i64::from(AdvisoryStore::SCHEMA_VERSION));
    }

    #[tokio::test]
    async fn upsert_advisory_is_idempotent() {
        let f = NamedTempFile::new().unwrap();
        let store = AdvisoryStore::new(f.path()).await.unwrap();

        store.upsert_advisory(&sample("ADV-1", 1)).await.unwrap();

        // Same id, refined payload (the operator overlay case).
        let mut refined = sample("ADV-1", 2);
        refined.severity = "critical".into();
        refined.source = "operator".into();
        refined.version_constraint = Some(r#"{"lt":"7.20"}"#.into());
        store.upsert_advisory(&refined).await.unwrap();

        let all = store.list_advisories().await.unwrap();
        assert_eq!(all.len(), 1, "advisory_id is the dedup key");
        assert_eq!(all[0].severity, "critical");
        assert_eq!(all[0].source, "operator");
        assert_eq!(all[0].catalog_version, 2);
        assert_eq!(
            all[0].version_constraint.as_deref(),
            Some(r#"{"lt":"7.20"}"#)
        );
        assert_eq!(all[0].requires_surface_names, vec!["api", "api-ssl"]);
        assert!(all[0].no_fixed_release);
    }

    #[tokio::test]
    async fn upsert_signal_enforces_confidence_check() {
        let f = NamedTempFile::new().unwrap();
        let store = AdvisoryStore::new(f.path()).await.unwrap();
        store.upsert_advisory(&sample("ADV-1", 1)).await.unwrap();

        store
            .upsert_signal("ADV-1", "sig.a", "strong", "d")
            .await
            .unwrap();
        store
            .upsert_signal("ADV-1", "sig.b", "corroborating", "d")
            .await
            .unwrap();

        let err = store
            .upsert_signal("ADV-1", "sig.c", "definitely", "d")
            .await
            .expect_err("CHECK must reject unknown confidence");
        assert!(err.contains("upsert_signal failed"), "got: {err}");

        assert!(
            store
                .advisories_for_signal("sig.c")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn advisories_for_signal_returns_pairs() {
        let f = NamedTempFile::new().unwrap();
        let store = AdvisoryStore::new(f.path()).await.unwrap();
        store.upsert_advisory(&sample("ADV-1", 1)).await.unwrap();
        store.upsert_advisory(&sample("ADV-2", 1)).await.unwrap();

        store
            .upsert_signal("ADV-1", "sig.shared", "strong", "d")
            .await
            .unwrap();
        store
            .upsert_signal("ADV-2", "sig.shared", "corroborating", "d")
            .await
            .unwrap();
        store
            .upsert_signal("ADV-1", "sig.other", "strong", "d")
            .await
            .unwrap();

        let shared = store.advisories_for_signal("sig.shared").await.unwrap();
        assert_eq!(
            shared,
            vec![
                ("ADV-1".to_string(), "strong".to_string()),
                ("ADV-2".to_string(), "corroborating".to_string()),
            ]
        );

        // Re-linking the same pair refines confidence rather than duplicating.
        store
            .upsert_signal("ADV-1", "sig.shared", "corroborating", "d2")
            .await
            .unwrap();
        let shared = store.advisories_for_signal("sig.shared").await.unwrap();
        assert_eq!(shared.len(), 2);
        assert_eq!(shared[0].1, "corroborating");

        let other = store.advisories_for_signal("sig.other").await.unwrap();
        assert_eq!(other, vec![("ADV-1".to_string(), "strong".to_string())]);
    }

    /// Build an advisory.db exactly as a Phase 1 (schema v1) binary left it:
    /// the v1 baseline DDL, a catalog row, an observation row, `user_version=1`.
    /// The DDL is copied verbatim from the v1 baseline rather than calling
    /// current code, so this fixture stays a v1 database even after the
    /// baseline moves on.
    fn create_v1_database(path: &Path) {
        let conn = Connection::open(path).expect("create v1 db");
        conn.execute_batch(
            "
            CREATE TABLE advisory (
                advisory_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                narrative TEXT NOT NULL,
                severity TEXT NOT NULL,
                requires_surface_class TEXT NOT NULL,
                requires_surface_names TEXT NOT NULL,
                requires_state TEXT NOT NULL,
                version_constraint TEXT,
                no_fixed_release INTEGER NOT NULL DEFAULT 0,
                fixed_versions TEXT NOT NULL,
                mitigations TEXT NOT NULL,
                references_json TEXT NOT NULL,
                attack_techniques TEXT NOT NULL,
                source TEXT NOT NULL,
                catalog_version INTEGER NOT NULL,
                generated_at TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE advisory_signal (
                advisory_id TEXT NOT NULL,
                signal_id TEXT NOT NULL,
                confidence TEXT NOT NULL
                    CHECK (confidence IN ('strong', 'corroborating')),
                description TEXT NOT NULL,
                PRIMARY KEY (advisory_id, signal_id)
            );

            CREATE INDEX idx_advisory_signal_signal
                ON advisory_signal(signal_id);

            CREATE TABLE advisory_attack_observation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                surface_key TEXT NOT NULL,
                signal_id TEXT NOT NULL,
                src_ips TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                observed_at INTEGER NOT NULL
            );

            CREATE INDEX idx_advisory_obs_surface
                ON advisory_attack_observation(surface_key, observed_at DESC);

            CREATE TABLE advisory_suppression (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                advisory_id TEXT NOT NULL,
                surface_key TEXT NOT NULL,
                reason TEXT,
                created_by TEXT,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                UNIQUE(advisory_id, surface_key)
            );

            INSERT INTO advisory VALUES (
                'ADV-V1', 'v1 title', 'v1 narrative', 'high', 'service',
                '[\"api\"]', '[\"exposed\"]', NULL, 1, '[]',
                '[\"restrict\"]', '[]', '[\"T1110\"]', 'bundled', 1,
                '2026-07-28', 1753000000
            );

            INSERT INTO advisory_attack_observation
                (device_id, surface_key, signal_id, src_ips, event_count, observed_at)
            VALUES
                ('dev-1', 'dev-1:svc:api', 'auth.login_failure_burst',
                 '[\"10.0.0.1\"]', 21, 1753000100);

            PRAGMA user_version = 1;
            ",
        )
        .expect("v1 fixture ddl");
    }

    fn table_exists(conn: &Connection, name: &str) -> bool {
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            params![name],
            |r| r.get::<_, i64>(0),
        )
        .expect("sqlite_master query")
            > 0
    }

    fn user_version(path: &Path) -> i64 {
        let conn = Connection::open(path).expect("open for version check");
        conn.query_row("PRAGMA user_version", [], |r| r.get(0))
            .expect("user_version")
    }

    #[tokio::test]
    async fn existing_v1_database_is_upgraded_in_place_to_v2() {
        let f = NamedTempFile::new().unwrap();
        create_v1_database(f.path());
        assert_eq!(user_version(f.path()), 1, "fixture must start at v1");

        // A v2 binary opening a v1 database on disk: this is the upgrade path.
        let store = AdvisoryStore::new(f.path()).await.expect("v1 db must open");

        assert_eq!(user_version(f.path()), 2, "v1 database migrates to v2");
        {
            let conn = Connection::open(f.path()).unwrap();
            assert!(
                table_exists(&conn, "advisory_auth_failure"),
                "v2 adds the auth-failure accumulator table"
            );
        }

        // The v1 data survived the migration and is readable through the
        // store's own APIs — upgraded in place, not recreated.
        let advisories = store.list_advisories().await.unwrap();
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].advisory_id, "ADV-V1");
        assert_eq!(advisories[0].requires_surface_names, vec!["api"]);

        let obs = store.observations_since(0).await.unwrap();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].event_count, 21);
        assert_eq!(obs[0].src_ips, vec!["10.0.0.1"]);
    }

    #[tokio::test]
    async fn migrated_database_reopens_without_rerunning_steps() {
        let f = NamedTempFile::new().unwrap();
        create_v1_database(f.path());

        // First open migrates; drop the store so the file is released.
        drop(AdvisoryStore::new(f.path()).await.expect("migrating open"));
        assert_eq!(user_version(f.path()), 2);

        // Second open must be a no-op: the migration step uses plain
        // CREATE TABLE, so a wrongly re-run step fails loudly here instead
        // of passing silently.
        drop(AdvisoryStore::new(f.path()).await.expect("reopen at v2"));
        assert_eq!(user_version(f.path()), 2);
    }

    #[tokio::test]
    async fn fresh_db_creates_v2_schema() {
        let f = NamedTempFile::new().unwrap();
        let _store = AdvisoryStore::new(f.path()).await.unwrap();

        assert_eq!(user_version(f.path()), 2, "fresh database lands on v2");
        let conn = Connection::open(f.path()).unwrap();
        assert!(table_exists(&conn, "advisory_auth_failure"));
    }

    #[tokio::test]
    async fn prune_observations_deletes_only_older_than_cutoff() {
        let f = NamedTempFile::new().unwrap();
        let store = AdvisoryStore::new(f.path()).await.unwrap();

        let ips = vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()];
        for observed_at in [100_i64, 200, 300] {
            store
                .record_observation(
                    "dev-1",
                    "service:api",
                    "auth.login_failure_burst",
                    &ips,
                    observed_at,
                    observed_at,
                )
                .await
                .unwrap();
        }

        let deleted = store.prune_observations(200).await.unwrap();
        assert_eq!(deleted, 1, "only the ts=100 row is older than the cutoff");

        let left = store.observations_since(0).await.unwrap();
        assert_eq!(left.len(), 2);
        assert_eq!(left[0].observed_at, 300, "newest first");
        assert_eq!(left[1].observed_at, 200, "cutoff row is retained");
        assert_eq!(left[0].src_ips, ips);
        assert_eq!(left[0].device_id, "dev-1");
        assert_eq!(left[0].surface_key, "service:api");
        assert_eq!(left[0].event_count, 300);

        // Window queries honour the cutoff too.
        let recent = store.observations_since(300).await.unwrap();
        assert_eq!(recent.len(), 1);
    }

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
        assert_eq!(
            recent.len(),
            1,
            "cutoff is inclusive-forward like observations_since"
        );
    }

    #[tokio::test]
    async fn prune_auth_failures_deletes_only_older_than_cutoff() {
        let f = NamedTempFile::new().unwrap();
        let store = AdvisoryStore::new(f.path()).await.unwrap();

        for ts in [100_i64, 200, 300] {
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
}
