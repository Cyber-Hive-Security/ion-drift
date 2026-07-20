//! Findings store — persistence for module-emitted findings.
//!
//! Findings are high-level narratives produced by registered modules and
//! pushed into Drift via the inbound publish endpoint. Drift owns the
//! lifecycle (open → acknowledged → resolved) and the row-level identity;
//! the emitting module owns the payload semantics.
//!
//! Dedup key is `(module_name, finding_id)` so a module can re-emit a
//! refined version of the same finding without creating duplicates.

use std::path::Path;
use std::sync::Arc;

use ion_drift_module_api::{FindingEvidence, FindingSeverity, FindingV1};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Acknowledged,
    Resolved,
}

impl FindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingStatus::Open => "open",
            FindingStatus::Acknowledged => "acknowledged",
            FindingStatus::Resolved => "resolved",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "acknowledged" => FindingStatus::Acknowledged,
            "resolved" => FindingStatus::Resolved,
            _ => FindingStatus::Open,
        }
    }
}

fn severity_as_str(sev: FindingSeverity) -> &'static str {
    match sev {
        FindingSeverity::Critical => "critical",
        FindingSeverity::High => "high",
        FindingSeverity::Medium => "medium",
        FindingSeverity::Low => "low",
        FindingSeverity::Info => "info",
    }
}

fn severity_from_str_lossy(s: &str) -> FindingSeverity {
    match s {
        "critical" => FindingSeverity::Critical,
        "high" => FindingSeverity::High,
        "medium" => FindingSeverity::Medium,
        "low" => FindingSeverity::Low,
        _ => FindingSeverity::Info,
    }
}

/// Hydrated finding row as stored in `findings.db`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: i64,
    pub module_name: String,
    pub finding_id: String,
    pub title: String,
    pub narrative: String,
    pub severity: FindingSeverity,
    pub category: String,
    pub recommended_actions: Vec<String>,
    pub evidence: Vec<FindingEvidence>,
    pub device_macs: Vec<String>,
    pub metadata: Option<serde_json::Value>,
    pub timestamp: i64,
    pub received_at: i64,
    pub envelope_event_id: Option<String>,
    pub envelope_nonce: Option<String>,
    pub status: FindingStatus,
    pub acknowledged_at: Option<i64>,
    pub acknowledged_by: Option<String>,
    pub resolved_at: Option<i64>,
    pub resolved_by: Option<String>,
    pub resolution_note: Option<String>,
}

/// Aggregate counts surfaced by `GET /api/findings/summary`. Severity
/// counts cover open findings only — resolved/acknowledged severities are
/// not actionable for the dashboard.
///
/// Field names use the `_count` suffix to match the Phase 4 plan reference
/// (`useFindingsSummary().data.open_count`). The severity-level fields keep
/// the `*_open` shape so the UI can pluck a single open-by-severity series
/// without indexing into a nested object.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FindingsSummary {
    pub total: i64,
    pub open_count: i64,
    pub acknowledged_count: i64,
    pub resolved_count: i64,
    pub critical_open: i64,
    pub high_open: i64,
    pub medium_open: i64,
    pub low_open: i64,
    pub info_open: i64,
}

/// Filter parameters for listing findings.
#[derive(Clone, Debug, Default)]
pub struct FindingsQuery {
    pub status: Option<FindingStatus>,
    pub severity: Option<FindingSeverity>,
    pub module_name: Option<String>,
    pub category: Option<String>,
    pub since: Option<i64>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub struct FindingsStore {
    db: Arc<Mutex<Connection>>,
}

impl FindingsStore {
    /// Schema version stamped into `PRAGMA user_version`. Bump when adding a
    /// versioned migration (see `crate::migrations`). v1 = the 0.5.x baseline.
    pub const SCHEMA_VERSION: u32 = 1;

    pub fn new(db_path: &Path) -> Result<Self, String> {
        let conn =
            Connection::open(db_path).map_err(|e| format!("failed to open findings db: {e}"))?;
        crate::migrations::open_guard(&conn, "findings.db", Self::SCHEMA_VERSION)?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| format!("pragma failed: {e}"))?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module_name TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                title TEXT NOT NULL,
                narrative TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                recommended_actions TEXT NOT NULL,
                evidence TEXT NOT NULL,
                device_macs TEXT NOT NULL,
                metadata TEXT,
                timestamp INTEGER NOT NULL,
                received_at INTEGER NOT NULL,
                envelope_event_id TEXT,
                envelope_nonce TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                acknowledged_at INTEGER,
                acknowledged_by TEXT,
                resolved_at INTEGER,
                resolved_by TEXT,
                resolution_note TEXT,
                UNIQUE(module_name, finding_id)
            );

            CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
            CREATE INDEX IF NOT EXISTS idx_findings_module ON findings(module_name);
            CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            ",
        )
        .map_err(|e| format!("schema creation failed: {e}"))?;

        crate::migrations::stamp(&conn, "findings.db", Self::SCHEMA_VERSION)?;

        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
        })
    }

    /// Insert a finding, or refine an existing row keyed by
    /// `(module_name, finding_id)`. Returns the row id.
    ///
    /// On conflict, lifecycle columns (status / ack / resolved) are
    /// preserved — re-emission updates the payload but does not reopen a
    /// finding the operator already actioned.
    pub async fn upsert_finding(
        &self,
        module_name: &str,
        finding: &FindingV1,
        envelope_event_id: Option<&str>,
        envelope_nonce: Option<&str>,
    ) -> Result<i64, String> {
        let recommended_actions = serde_json::to_string(&finding.recommended_actions)
            .map_err(|e| format!("serialize recommended_actions: {e}"))?;
        let evidence = serde_json::to_string(&finding.evidence)
            .map_err(|e| format!("serialize evidence: {e}"))?;
        let device_macs = serde_json::to_string(&finding.device_macs)
            .map_err(|e| format!("serialize device_macs: {e}"))?;
        let metadata = match &finding.metadata {
            Some(v) => Some(
                serde_json::to_string(v).map_err(|e| format!("serialize metadata: {e}"))?,
            ),
            None => None,
        };

        let db = self.db.lock().await;
        let now = now_unix();
        db.execute(
            "INSERT INTO findings
                (module_name, finding_id, title, narrative, severity, category,
                 recommended_actions, evidence, device_macs, metadata,
                 timestamp, received_at, envelope_event_id, envelope_nonce, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 'open')
             ON CONFLICT(module_name, finding_id) DO UPDATE SET
                title = excluded.title,
                narrative = excluded.narrative,
                severity = excluded.severity,
                category = excluded.category,
                recommended_actions = excluded.recommended_actions,
                evidence = excluded.evidence,
                device_macs = excluded.device_macs,
                metadata = excluded.metadata,
                timestamp = excluded.timestamp,
                envelope_event_id = excluded.envelope_event_id,
                envelope_nonce = excluded.envelope_nonce",
            params![
                module_name,
                finding.finding_id,
                finding.title,
                finding.narrative,
                severity_as_str(finding.severity),
                finding.category,
                recommended_actions,
                evidence,
                device_macs,
                metadata,
                finding.timestamp_unix,
                now,
                envelope_event_id,
                envelope_nonce,
            ],
        )
        .map_err(|e| format!("upsert_finding failed: {e}"))?;

        let id: i64 = db
            .query_row(
                "SELECT id FROM findings WHERE module_name = ?1 AND finding_id = ?2",
                params![module_name, finding.finding_id],
                |row| row.get(0),
            )
            .map_err(|e| format!("upsert_finding lookup failed: {e}"))?;
        Ok(id)
    }

    pub async fn list_findings(&self, query: &FindingsQuery) -> Result<Vec<Finding>, String> {
        let db = self.db.lock().await;
        let mut sql = String::from(
            "SELECT id, module_name, finding_id, title, narrative, severity, category,
                    recommended_actions, evidence, device_macs, metadata,
                    timestamp, received_at, envelope_event_id, envelope_nonce,
                    status, acknowledged_at, acknowledged_by,
                    resolved_at, resolved_by, resolution_note
             FROM findings WHERE 1=1",
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(status) = query.status {
            param_values.push(Box::new(status.as_str().to_string()));
            sql.push_str(&format!(" AND status = ?{}", param_values.len()));
        }
        if let Some(severity) = query.severity {
            param_values.push(Box::new(severity_as_str(severity).to_string()));
            sql.push_str(&format!(" AND severity = ?{}", param_values.len()));
        }
        if let Some(module_name) = &query.module_name {
            param_values.push(Box::new(module_name.clone()));
            sql.push_str(&format!(" AND module_name = ?{}", param_values.len()));
        }
        if let Some(category) = &query.category {
            param_values.push(Box::new(category.clone()));
            sql.push_str(&format!(" AND category = ?{}", param_values.len()));
        }
        if let Some(since) = query.since {
            param_values.push(Box::new(since));
            sql.push_str(&format!(" AND timestamp >= ?{}", param_values.len()));
        }
        sql.push_str(" ORDER BY timestamp DESC");
        if let Some(limit) = query.limit {
            param_values.push(Box::new(limit));
            sql.push_str(&format!(" LIMIT ?{}", param_values.len()));
        }
        if let Some(offset) = query.offset {
            param_values.push(Box::new(offset));
            sql.push_str(&format!(" OFFSET ?{}", param_values.len()));
        }

        let mut stmt = db
            .prepare(&sql)
            .map_err(|e| format!("prepare failed: {e}"))?;
        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(params_ref.as_slice(), Self::map_row)
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))
    }

    pub async fn get_finding(&self, id: i64) -> Result<Option<Finding>, String> {
        let db = self.db.lock().await;
        db.query_row(
            "SELECT id, module_name, finding_id, title, narrative, severity, category,
                    recommended_actions, evidence, device_macs, metadata,
                    timestamp, received_at, envelope_event_id, envelope_nonce,
                    status, acknowledged_at, acknowledged_by,
                    resolved_at, resolved_by, resolution_note
             FROM findings WHERE id = ?1",
            params![id],
            Self::map_row,
        )
        .optional()
        .map_err(|e| format!("get_finding failed: {e}"))
    }

    pub async fn acknowledge(&self, id: i64, user: &str) -> Result<(), String> {
        let db = self.db.lock().await;
        let now = now_unix();
        let updated = db
            .execute(
                "UPDATE findings
                 SET status = 'acknowledged', acknowledged_at = ?1, acknowledged_by = ?2
                 WHERE id = ?3 AND status = 'open'",
                params![now, user, id],
            )
            .map_err(|e| format!("acknowledge failed: {e}"))?;
        if updated == 0 {
            return Err(format!("finding {id} not open or not found"));
        }
        Ok(())
    }

    pub async fn resolve(
        &self,
        id: i64,
        user: &str,
        note: Option<String>,
    ) -> Result<(), String> {
        let db = self.db.lock().await;
        let now = now_unix();
        let updated = db
            .execute(
                "UPDATE findings
                 SET status = 'resolved',
                     resolved_at = ?1,
                     resolved_by = ?2,
                     resolution_note = ?3
                 WHERE id = ?4 AND status IN ('open', 'acknowledged')",
                params![now, user, note, id],
            )
            .map_err(|e| format!("resolve failed: {e}"))?;
        if updated == 0 {
            return Err(format!("finding {id} not open/acknowledged or not found"));
        }
        Ok(())
    }

    pub async fn summary(&self) -> Result<FindingsSummary, String> {
        let db = self.db.lock().await;
        db.query_row(
            "SELECT
                COUNT(*) AS total,
                COALESCE(SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END), 0) AS opn,
                COALESCE(SUM(CASE WHEN status = 'acknowledged' THEN 1 ELSE 0 END), 0) AS ackd,
                COALESCE(SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END), 0) AS rslv,
                COALESCE(SUM(CASE WHEN status = 'open' AND severity = 'critical' THEN 1 ELSE 0 END), 0) AS critical_open,
                COALESCE(SUM(CASE WHEN status = 'open' AND severity = 'high' THEN 1 ELSE 0 END), 0) AS high_open,
                COALESCE(SUM(CASE WHEN status = 'open' AND severity = 'medium' THEN 1 ELSE 0 END), 0) AS medium_open,
                COALESCE(SUM(CASE WHEN status = 'open' AND severity = 'low' THEN 1 ELSE 0 END), 0) AS low_open,
                COALESCE(SUM(CASE WHEN status = 'open' AND severity = 'info' THEN 1 ELSE 0 END), 0) AS info_open
             FROM findings",
            [],
            |row| {
                Ok(FindingsSummary {
                    total: row.get(0)?,
                    open_count: row.get(1)?,
                    acknowledged_count: row.get(2)?,
                    resolved_count: row.get(3)?,
                    critical_open: row.get(4)?,
                    high_open: row.get(5)?,
                    medium_open: row.get(6)?,
                    low_open: row.get(7)?,
                    info_open: row.get(8)?,
                })
            },
        )
        .map_err(|e| format!("summary failed: {e}"))
    }

    /// Auto-resolve stale `open` findings older than `cutoff_secs`,
    /// **never** touching severity in {critical, high}. Returns the count
    /// of rows resolved. Mirrors the policy used by the behavior store.
    pub async fn auto_resolve_stale(&self, cutoff_secs: i64) -> Result<usize, String> {
        let db = self.db.lock().await;
        let now = now_unix();
        let cutoff = now - cutoff_secs;
        let count = db
            .execute(
                "UPDATE findings
                 SET status = 'resolved',
                     resolved_at = ?1,
                     resolved_by = 'system',
                     resolution_note = 'auto-resolved: stale'
                 WHERE status = 'open'
                   AND severity NOT IN ('critical', 'high')
                   AND timestamp < ?2",
                params![now, cutoff],
            )
            .map_err(|e| format!("auto_resolve_stale failed: {e}"))?;
        Ok(count)
    }

    fn map_row(row: &Row<'_>) -> rusqlite::Result<Finding> {
        let recommended_actions_json: String = row.get(7)?;
        let evidence_json: String = row.get(8)?;
        let device_macs_json: String = row.get(9)?;
        let metadata_json: Option<String> = row.get(10)?;
        let severity_str: String = row.get(5)?;
        let status_str: String = row.get(15)?;

        let recommended_actions = serde_json::from_str(&recommended_actions_json)
            .unwrap_or_default();
        let evidence = serde_json::from_str(&evidence_json).unwrap_or_default();
        let device_macs = serde_json::from_str(&device_macs_json).unwrap_or_default();
        let metadata = metadata_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok());

        Ok(Finding {
            id: row.get(0)?,
            module_name: row.get(1)?,
            finding_id: row.get(2)?,
            title: row.get(3)?,
            narrative: row.get(4)?,
            severity: severity_from_str_lossy(&severity_str),
            category: row.get(6)?,
            recommended_actions,
            evidence,
            device_macs,
            metadata,
            timestamp: row.get(11)?,
            received_at: row.get(12)?,
            envelope_event_id: row.get(13)?,
            envelope_nonce: row.get(14)?,
            status: FindingStatus::from_str_lossy(&status_str),
            acknowledged_at: row.get(16)?,
            acknowledged_by: row.get(17)?,
            resolved_at: row.get(18)?,
            resolved_by: row.get(19)?,
            resolution_note: row.get(20)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ion_drift_module_api::{FindingEvidence, FindingSeverity};
    use tempfile::NamedTempFile;

    fn sample(id: &str, sev: FindingSeverity) -> FindingV1 {
        FindingV1 {
            finding_id: id.to_string(),
            title: "title".into(),
            narrative: "narrative".into(),
            severity: sev,
            category: "test".into(),
            recommended_actions: vec!["do thing".into()],
            evidence: vec![FindingEvidence::Anomaly { anomaly_id: 7 }],
            device_macs: vec!["aa:bb:cc:dd:ee:ff".into()],
            timestamp_unix: 1_700_000_000,
            metadata: Some(serde_json::json!({"k": "v"})),
        }
    }

    #[tokio::test]
    async fn round_trip_and_dedup() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();

        let id1 = store
            .upsert_finding("sample-engine", &sample("a", FindingSeverity::Medium), None, None)
            .await
            .unwrap();
        let id2 = store
            .upsert_finding(
                "sample-engine",
                &sample("a", FindingSeverity::High),
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(id1, id2, "dedup keyed on (module_name, finding_id)");

        let got = store.get_finding(id1).await.unwrap().unwrap();
        assert_eq!(got.severity as i32, FindingSeverity::High as i32);
        assert_eq!(got.module_name, "sample-engine");
        assert_eq!(got.evidence.len(), 1);

        let all = store
            .list_findings(&FindingsQuery::default())
            .await
            .unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn lifecycle_transitions() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let id = store
            .upsert_finding("m", &sample("x", FindingSeverity::Low), None, None)
            .await
            .unwrap();

        store.acknowledge(id, "alice").await.unwrap();
        assert_eq!(
            store.get_finding(id).await.unwrap().unwrap().status,
            FindingStatus::Acknowledged
        );

        // ack on already-ack'd finding fails
        assert!(store.acknowledge(id, "alice").await.is_err());

        store
            .resolve(id, "alice", Some("done".into()))
            .await
            .unwrap();
        let got = store.get_finding(id).await.unwrap().unwrap();
        assert_eq!(got.status, FindingStatus::Resolved);
        assert_eq!(got.resolution_note.as_deref(), Some("done"));
    }

    #[tokio::test]
    async fn summary_buckets_by_status_and_open_severity() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();

        // 1 critical open, 1 high open, 1 low open, 1 medium acknowledged, 1 info resolved.
        let id_med = store
            .upsert_finding("m", &sample("med", FindingSeverity::Medium), None, None)
            .await
            .unwrap();
        store.acknowledge(id_med, "alice").await.unwrap();

        let id_info = store
            .upsert_finding("m", &sample("info", FindingSeverity::Info), None, None)
            .await
            .unwrap();
        store.resolve(id_info, "alice", None).await.unwrap();

        store
            .upsert_finding("m", &sample("crit", FindingSeverity::Critical), None, None)
            .await
            .unwrap();
        store
            .upsert_finding("m", &sample("hi", FindingSeverity::High), None, None)
            .await
            .unwrap();
        store
            .upsert_finding("m", &sample("lo", FindingSeverity::Low), None, None)
            .await
            .unwrap();

        let s = store.summary().await.unwrap();
        assert_eq!(s.total, 5);
        assert_eq!(s.open_count, 3);
        assert_eq!(s.acknowledged_count, 1);
        assert_eq!(s.resolved_count, 1);
        assert_eq!(s.critical_open, 1);
        assert_eq!(s.high_open, 1);
        assert_eq!(s.medium_open, 0, "ack'd medium must not count as open");
        assert_eq!(s.low_open, 1);
        assert_eq!(s.info_open, 0, "resolved info must not count as open");
    }

    #[tokio::test]
    async fn auto_resolve_protects_high_and_critical() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();

        // Backdate timestamps so cutoff catches them
        let mut low = sample("low", FindingSeverity::Low);
        low.timestamp_unix = 0;
        let mut crit = sample("crit", FindingSeverity::Critical);
        crit.timestamp_unix = 0;
        let mut high = sample("high", FindingSeverity::High);
        high.timestamp_unix = 0;

        store.upsert_finding("m", &low, None, None).await.unwrap();
        store.upsert_finding("m", &crit, None, None).await.unwrap();
        store.upsert_finding("m", &high, None, None).await.unwrap();

        // cutoff 1 second — everything is older
        let n = store.auto_resolve_stale(1).await.unwrap();
        assert_eq!(n, 1, "only the low-severity one auto-resolves");

        let open = store
            .list_findings(&FindingsQuery {
                status: Some(FindingStatus::Open),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(open.len(), 2);
    }
}
