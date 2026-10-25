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

use ion_drift_module_api::{FindingEvidence, FindingSeverity, FindingSubject, FindingV1};
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
    pub subjects: Vec<FindingSubject>,
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

/// The resolution [`FindingsStore::reopen_by_key`] cleared off a row it
/// re-opened.
///
/// Returned rather than discarded so the caller can carry the record into the
/// re-opened finding as evidence. A re-open has to win over any resolution — a
/// live attack must be visible — but the operator's account of what they did
/// about it is worth keeping, and this is what keeps "reopen anyway" from
/// meaning "destroy the note".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorResolution {
    /// Who resolved it: an operator's username, or `system` for the engine's own
    /// close-out. `unknown` when the row carried no attribution at all.
    pub resolved_by: String,
    /// When, in unix seconds. `0` when the row carried no timestamp.
    pub resolved_at: i64,
    /// The note they left, if any.
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
    pub const SCHEMA_VERSION: u32 = 2;

    /// Versioned migrations applied after the v1 baseline, in ascending order.
    ///
    /// v2 — `subjects` (0.5.6). Existing rows get their `device_macs` folded in
    /// as endpoint subjects so nothing already on the page loses its devices.
    const MIGRATION_STEPS: &'static [(u32, &'static str)] = &[(
        2,
        "ALTER TABLE findings ADD COLUMN subjects TEXT NOT NULL DEFAULT '[]';
         UPDATE findings SET subjects = (
             SELECT json_group_array(json_object('kind', 'endpoint', 'id', value))
             FROM json_each(findings.device_macs))
         WHERE device_macs != '[]';",
    )];

    pub fn new(db_path: &Path) -> Result<Self, String> {
        let mut conn =
            Connection::open(db_path).map_err(|e| format!("failed to open findings db: {e}"))?;
        let db_version =
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

        crate::migrations::apply_versioned(
            &mut conn,
            "findings.db",
            db_version,
            Self::MIGRATION_STEPS,
        )?;
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
        let subjects = serde_json::to_string(&finding.all_subjects())
            .map_err(|e| format!("serialize subjects: {e}"))?;
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
                 timestamp, received_at, envelope_event_id, envelope_nonce, subjects, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 'open')
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
                envelope_nonce = excluded.envelope_nonce,
                subjects = excluded.subjects",
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
                subjects,
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
                    resolved_at, resolved_by, resolution_note, subjects
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
                    resolved_at, resolved_by, resolution_note, subjects
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

    /// Resolve a finding by its dedup key rather than its row id, so an
    /// engine that re-derives a `finding_id` can close its own finding out
    /// without first looking up the row.
    ///
    /// `upsert_finding` deliberately preserves lifecycle state on conflict and
    /// `auto_resolve_stale` exempts critical/high, so without this a finding
    /// whose underlying condition has cleared would stay open forever.
    ///
    /// Returns `Ok(false)` when no open/acknowledged row matches — this is not
    /// an error, it just means the finding was never raised or is already
    /// resolved, which makes repeated calls idempotent.
    pub async fn resolve_by_key(
        &self,
        module_name: &str,
        finding_id: &str,
        note: &str,
    ) -> Result<bool, String> {
        let db = self.db.lock().await;
        let now = now_unix();
        let updated = db
            .execute(
                "UPDATE findings
                 SET status = 'resolved',
                     resolved_at = ?1,
                     resolved_by = 'system',
                     resolution_note = ?2
                 WHERE module_name = ?3
                   AND finding_id = ?4
                   AND status IN ('open', 'acknowledged')",
                params![now, note, module_name, finding_id],
            )
            .map_err(|e| format!("resolve_by_key failed: {e}"))?;
        Ok(updated > 0)
    }

    /// Re-open a resolved finding whose condition an engine has observed again,
    /// keyed the same way as [`Self::resolve_by_key`].
    ///
    /// `upsert_finding` deliberately preserves lifecycle state on conflict so a
    /// re-emission cannot undo an operator's triage. That is right for a
    /// finding whose condition genuinely cleared, but an engine re-observing
    /// the condition itself needs a way to say so: without this, a live attack
    /// that pauses long enough to be closed out and then resumes refreshes the
    /// row's body while the row stays `resolved` — kept out of
    /// `GET /api/findings?status=open` and out of `critical_open` for good.
    ///
    /// Only a `resolved` row is touched. An `acknowledged` one is a live triage
    /// decision on a still-open finding and is left exactly as the operator set
    /// it.
    ///
    /// A row resolved by *anyone* re-opens, the operator included, and the
    /// tradeoff is deliberate. Restricting this to `resolved_by = 'system'`
    /// stopped the engine from undoing operator triage on its own schedule, but
    /// it bought that with the worse failure in the opposite direction: an
    /// operator who resolves an exploitation finding during a lull silences the
    /// same attack permanently when it resumes — no open row, nothing in
    /// `critical_open`, no alert, and no way back short of a manual DB edit. A
    /// finding that reappears when it should not is an annoyance an operator can
    /// see and act on; a live attack with no finding is invisible by
    /// construction. For a security product only one of those is survivable.
    ///
    /// What the operator wrote is preserved rather than destroyed. The
    /// resolution being cleared is *returned* as a [`PriorResolution`] so the
    /// caller can fold it into the re-opened finding as evidence — "previously
    /// resolved by <who> on <date>: <note>" — which keeps their account of what
    /// they did attached to the finding instead of suppressing it. `None` means
    /// no row changed (already open, acknowledged, or absent), so repeated calls
    /// stay idempotent and a caller can tell a genuine re-open from a no-op.
    ///
    /// Resolving is a statement about *this* occurrence, not a standing
    /// instruction to stay quiet. Durable suppression is a different feature and
    /// belongs in the `advisory_suppression` table, which is **not wired up
    /// yet** — until it is, an operator who wants a finding to stay closed has
    /// to remove the condition producing it.
    ///
    /// Acknowledgement stamps are cleared along with the resolution. They belong
    /// to the incarnation that was closed out; carrying them across would show a
    /// freshly re-opened finding as already acknowledged by someone who never
    /// saw this occurrence of it, and hide it from anyone triaging by ack state.
    pub async fn reopen_by_key(
        &self,
        module_name: &str,
        finding_id: &str,
    ) -> Result<Option<PriorResolution>, String> {
        let db = self.db.lock().await;
        // Read before clearing: the UPDATE decides whether a row changed, but by
        // the time it has run the row no longer carries what was cleared. Both
        // statements run under the store's single connection lock, so nothing
        // can slip between them.
        let prior: Option<(Option<String>, Option<i64>, Option<String>)> = db
            .query_row(
                "SELECT resolved_by, resolved_at, resolution_note
                 FROM findings
                 WHERE module_name = ?1 AND finding_id = ?2 AND status = 'resolved'",
                params![module_name, finding_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|e| format!("reopen_by_key lookup failed: {e}"))?;

        let updated = db
            .execute(
                "UPDATE findings
                 SET status = 'open',
                     resolved_at = NULL,
                     resolved_by = NULL,
                     resolution_note = NULL,
                     acknowledged_at = NULL,
                     acknowledged_by = NULL
                 WHERE module_name = ?1
                   AND finding_id = ?2
                   AND status = 'resolved'",
                params![module_name, finding_id],
            )
            .map_err(|e| format!("reopen_by_key failed: {e}"))?;
        if updated == 0 {
            return Ok(None);
        }

        let (resolved_by, resolved_at, resolution_note) = prior.unwrap_or_default();
        Ok(Some(PriorResolution {
            // Every path that resolves a row stamps both columns, so a NULL here
            // means the row was written outside this API. Report it as unknown
            // rather than dropping the record — the caller asked what was
            // cleared, and "something was" is still the honest answer.
            resolved_by: resolved_by.unwrap_or_else(|| "unknown".to_string()),
            resolved_at: resolved_at.unwrap_or(0),
            resolution_note,
        }))
    }

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
        let subjects_json: String = row.get(21)?;
        let metadata_json: Option<String> = row.get(10)?;
        let severity_str: String = row.get(5)?;
        let status_str: String = row.get(15)?;

        let recommended_actions = serde_json::from_str(&recommended_actions_json)
            .unwrap_or_default();
        let evidence = serde_json::from_str(&evidence_json).unwrap_or_default();
        let device_macs = serde_json::from_str(&device_macs_json).unwrap_or_default();
        let subjects = serde_json::from_str(&subjects_json).unwrap_or_default();
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
            subjects,
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
            subjects: vec![],
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

    #[tokio::test]
    async fn resolve_by_key_closes_open_finding_and_is_idempotent() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();

        // Critical is deliberate: auto_resolve_stale exempts it in SQL, so a
        // by-key close-out is the only way this finding ever leaves 'open'.
        let id_a = store
            .upsert_finding("m", &sample("a", FindingSeverity::Critical), None, None)
            .await
            .unwrap();

        let closed = store
            .resolve_by_key("m", "a", "condition cleared")
            .await
            .unwrap();
        assert!(closed, "first close must report a resolved row");

        let found = store.get_finding(id_a).await.unwrap().unwrap();
        assert_eq!(found.status, FindingStatus::Resolved);
        assert_eq!(found.resolved_by.as_deref(), Some("system"));
        assert_eq!(found.resolution_note.as_deref(), Some("condition cleared"));

        // Idempotent: nothing left to close, and not an error.
        let again = store
            .resolve_by_key("m", "a", "condition cleared")
            .await
            .unwrap();
        assert!(!again, "second close must be a no-op");

        // Unknown keys are a no-op too, not an error.
        assert!(!store.resolve_by_key("m", "nope", "x").await.unwrap());
        assert!(!store.resolve_by_key("other", "a", "x").await.unwrap());

        // Acknowledged findings are closeable; already-resolved ones are not
        // re-opened or re-stamped by a later call.
        let id_b = store
            .upsert_finding("m", &sample("b", FindingSeverity::High), None, None)
            .await
            .unwrap();
        store.acknowledge(id_b, "alice").await.unwrap();
        assert!(store.resolve_by_key("m", "b", "cleared").await.unwrap());
    }

    /// The lifecycle an in-progress attack actually takes: seen, quiet long
    /// enough to be closed out, then seen again. `upsert_finding` preserves
    /// lifecycle state on conflict, so re-emitting alone refreshes the body and
    /// leaves the row `resolved` — out of `?status=open` and out of
    /// `critical_open` while the attack is live.
    #[tokio::test]
    async fn exploit_finding_reopens_after_close() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let key = "rb4011:svc:api:CVE-2026-16347:exploit";

        let id = store
            .upsert_finding("advisory", &sample(key, FindingSeverity::Critical), None, None)
            .await
            .unwrap();
        assert_eq!(
            store.get_finding(id).await.unwrap().unwrap().status,
            FindingStatus::Open
        );

        // The attack pauses; the evaluator closes it out.
        assert!(
            store
                .resolve_by_key("advisory", key, "exploitation signal ceased")
                .await
                .unwrap()
        );
        assert_eq!(store.summary().await.unwrap().critical_open, 0);

        // It resumes: the evaluator re-emits and re-opens.
        store
            .upsert_finding("advisory", &sample(key, FindingSeverity::Critical), None, None)
            .await
            .unwrap();
        let prior = store
            .reopen_by_key("advisory", key)
            .await
            .unwrap()
            .expect("a re-observed finding must come back");
        assert_eq!(prior.resolved_by, "system");
        assert_eq!(
            prior.resolution_note.as_deref(),
            Some("exploitation signal ceased")
        );

        let got = store.get_finding(id).await.unwrap().unwrap();
        assert_eq!(got.status, FindingStatus::Open);
        assert_eq!(got.resolved_at, None);
        assert_eq!(got.resolved_by, None);
        assert_eq!(got.resolution_note, None);
        assert_eq!(store.summary().await.unwrap().critical_open, 1);

        let open = store
            .list_findings(&FindingsQuery {
                status: Some(FindingStatus::Open),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(open.len(), 1, "the live attack must be listed as open");

        // Idempotent, and never overrides a live triage decision: an
        // acknowledged finding is left exactly as the operator set it.
        assert!(store.reopen_by_key("advisory", key).await.unwrap().is_none());
        assert!(
            store
                .reopen_by_key("advisory", "no-such-key")
                .await
                .unwrap()
                .is_none()
        );
        store.acknowledge(id, "alice").await.unwrap();
        assert!(store.reopen_by_key("advisory", key).await.unwrap().is_none());
        assert_eq!(
            store.get_finding(id).await.unwrap().unwrap().status,
            FindingStatus::Acknowledged
        );
    }

    /// A no-op has to be distinguishable from a genuine re-open, or a caller
    /// folding the cleared resolution into its evidence would re-derive it on
    /// every cycle for a finding that never left `open`.
    #[tokio::test]
    async fn reopen_returns_none_when_already_open() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();

        let id = store
            .upsert_finding("advisory", &sample("k", FindingSeverity::Critical), None, None)
            .await
            .unwrap();
        assert_eq!(
            store.get_finding(id).await.unwrap().unwrap().status,
            FindingStatus::Open
        );

        assert!(
            store.reopen_by_key("advisory", "k").await.unwrap().is_none(),
            "an already-open row has no resolution to clear"
        );
        assert_eq!(
            store.get_finding(id).await.unwrap().unwrap().status,
            FindingStatus::Open,
            "and is left exactly as it was"
        );

        // Same for a key that names nothing at all.
        assert!(
            store
                .reopen_by_key("advisory", "never-raised")
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.reopen_by_key("other", "k").await.unwrap().is_none());
    }

    /// An attack that resumes has to become visible again, whoever closed the
    /// finding out.
    ///
    /// Exempting operator-resolved rows kept their note safe but silenced the
    /// resumption: the operator resolves during a lull, the attack comes back,
    /// and there is no open finding, nothing in `critical_open`, and no alert —
    /// permanently, because nothing in the engine can ever flip that row again.
    /// So the re-open wins, and the operator's record is preserved by being
    /// *returned* to the caller as evidence rather than by suppressing the
    /// finding. Both halves are asserted here: the row comes back open and
    /// un-triaged, and nothing about alice's decision is silently dropped.
    #[tokio::test]
    async fn operator_resolved_finding_reopens_when_attack_resumes() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let key = "rb4011:svc:api:CVE-2026-16347:exploit";

        let id = store
            .upsert_finding("advisory", &sample(key, FindingSeverity::Critical), None, None)
            .await
            .unwrap();
        store.acknowledge(id, "bob").await.unwrap();
        store
            .resolve(id, "alice", Some("api restricted to mgmt vlan".into()))
            .await
            .unwrap();
        assert_eq!(store.summary().await.unwrap().critical_open, 0);

        // The attack resumes and the evaluator re-observes it.
        let prior = store
            .reopen_by_key("advisory", key)
            .await
            .unwrap()
            .expect("a live attack must come back regardless of who closed it");
        assert_eq!(prior.resolved_by, "alice");
        assert_eq!(
            prior.resolution_note.as_deref(),
            Some("api restricted to mgmt vlan"),
            "the operator's note is handed back, not destroyed"
        );
        assert!(prior.resolved_at > 0, "and dated, so evidence can say when");

        let got = store.get_finding(id).await.unwrap().unwrap();
        assert_eq!(got.status, FindingStatus::Open);
        assert_eq!(got.resolved_at, None);
        assert_eq!(got.resolved_by, None);
        assert_eq!(got.resolution_note, None);
        assert_eq!(
            got.acknowledged_by, None,
            "an open row must not carry triage state from the closed-out incarnation"
        );
        assert_eq!(got.acknowledged_at, None);
        assert_eq!(
            store.summary().await.unwrap().critical_open,
            1,
            "the resumed attack must be counted again"
        );

        // The evaluator keeps asking every cycle; only the first ask changed
        // anything, so the note is reported exactly once.
        for _ in 0..3 {
            assert!(store.reopen_by_key("advisory", key).await.unwrap().is_none());
        }
    }

    /// The engine's own close-outs re-open too, and a re-opened finding carries
    /// no acknowledgement from the incarnation that was closed out, or it
    /// returns already-triaged by someone who never saw this occurrence.
    #[tokio::test]
    async fn engine_resolved_finding_is_reopened_and_ack_stamps_cleared() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let key = "rb4011:svc:api:CVE-2026-16347:exploit";

        let id = store
            .upsert_finding("advisory", &sample(key, FindingSeverity::Critical), None, None)
            .await
            .unwrap();
        // Acknowledged during the first run, then the attack pauses and the
        // engine closes it out.
        store.acknowledge(id, "bob").await.unwrap();
        assert!(
            store
                .resolve_by_key("advisory", key, "exploitation signal ceased")
                .await
                .unwrap()
        );
        assert_eq!(
            store.get_finding(id).await.unwrap().unwrap().acknowledged_by.as_deref(),
            Some("bob"),
            "the closed-out row still carries the ack it was closed with"
        );

        // It resumes.
        let prior = store
            .reopen_by_key("advisory", key)
            .await
            .unwrap()
            .expect("a finding the engine closed must come back when the signal does");
        assert_eq!(prior.resolved_by, "system");
        let got = store.get_finding(id).await.unwrap().unwrap();
        assert_eq!(got.status, FindingStatus::Open);
        assert_eq!(got.resolved_by, None);
        assert_eq!(got.resolution_note, None);
        assert_eq!(
            got.acknowledged_by, None,
            "a re-opened finding must not show as acknowledged by the previous incarnation's triager"
        );
        assert_eq!(got.acknowledged_at, None);
        assert_eq!(store.summary().await.unwrap().critical_open, 1);

        // `auto_resolve_stale` also stamps 'system', so what it closed is
        // likewise the engine's to re-open.
        let mut stale = sample("stale-key", FindingSeverity::Low);
        stale.timestamp_unix = 0;
        store.upsert_finding("advisory", &stale, None, None).await.unwrap();
        assert_eq!(store.auto_resolve_stale(3600).await.unwrap(), 1);
        let stale_prior = store
            .reopen_by_key("advisory", "stale-key")
            .await
            .unwrap()
            .expect("an auto-resolved row re-opens too");
        assert_eq!(stale_prior.resolved_by, "system");
        assert_eq!(
            stale_prior.resolution_note.as_deref(),
            Some("auto-resolved: stale")
        );
    }

    fn escalation_finding(id: &str) -> FindingV1 {
        FindingV1 {
            finding_id: id.into(),
            title: "t".into(),
            narrative: "n".into(),
            severity: FindingSeverity::Low,
            category: "advisory_exposure".into(),
            recommended_actions: vec![],
            evidence: vec![],
            subjects: vec![],
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
}
