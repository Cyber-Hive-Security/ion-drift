//! Findings carry `references` (URLs) as a first-class list; findings.db v3
//! adds the column and older databases upgrade in place.

use std::path::PathBuf;

use ion_drift_module_api::{FindingEvidence, FindingSeverity, FindingV1};
use ion_drift_storage::findings::FindingsQuery;
use ion_drift_storage::FindingsStore;
use tempfile::tempdir;

const NVD: &str = "https://nvd.nist.gov/vuln/detail/CVE-2026-86060";

fn db_path() -> PathBuf {
    tempdir().expect("tempdir").keep().join("findings.db")
}

fn finding(references: Vec<String>) -> FindingV1 {
    FindingV1 {
        finding_id: "f-1".to_string(),
        title: "title".to_string(),
        narrative: "narrative".to_string(),
        severity: FindingSeverity::Medium,
        category: "test".to_string(),
        recommended_actions: vec![],
        evidence: vec![FindingEvidence::Anomaly { anomaly_id: 1 }],
        references,
        subjects: vec![],
        device_macs: vec![],
        timestamp_unix: 1_700_000_000,
        metadata: None,
    }
}

#[tokio::test]
async fn references_round_trip() {
    let store = FindingsStore::new(&db_path()).expect("findings store");
    store.upsert_finding("advisory", &finding(vec![]), None, None).await.expect("upsert");
    let rows = store.list_findings(&FindingsQuery::default()).await.expect("list");
    assert!(rows[0].references.is_empty());

    // Re-emitting replaces the list: the only "backfill" the v3 migration relies on.
    store
        .upsert_finding("advisory", &finding(vec![NVD.into()]), None, None)
        .await
        .expect("re-upsert");
    let one = store.get_finding(rows[0].id).await.expect("get").expect("row");
    assert_eq!(one.references, vec![NVD.to_string()]);
    let rows = store.list_findings(&FindingsQuery::default()).await.expect("list");
    assert_eq!(rows[0].references, vec![NVD.to_string()], "list SELECT serves the same column");
}

#[tokio::test]
async fn v2_database_upgrades_to_v3_with_empty_references() {
    let path = db_path();
    {
        // A findings.db as 0.5.6-dev wrote it at v2: subjects present, no references column.
        let db = rusqlite::Connection::open(&path).expect("open");
        db.execute_batch(
            "CREATE TABLE findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module_name TEXT NOT NULL, finding_id TEXT NOT NULL, title TEXT NOT NULL,
                narrative TEXT NOT NULL, severity TEXT NOT NULL, category TEXT NOT NULL,
                recommended_actions TEXT NOT NULL, evidence TEXT NOT NULL,
                device_macs TEXT NOT NULL, metadata TEXT, timestamp INTEGER NOT NULL,
                received_at INTEGER NOT NULL, envelope_event_id TEXT, envelope_nonce TEXT,
                status TEXT NOT NULL DEFAULT 'open', acknowledged_at INTEGER,
                acknowledged_by TEXT, resolved_at INTEGER, resolved_by TEXT,
                resolution_note TEXT, subjects TEXT NOT NULL DEFAULT '[]',
                UNIQUE(module_name, finding_id));
             INSERT INTO findings (module_name, finding_id, title, narrative, severity, category,
                recommended_actions, evidence, device_macs, timestamp, received_at)
             VALUES ('m', 'old', 't', 'n', 'low', 'c', '[]', '[]', '[]', 1, 1);
             PRAGMA user_version = 2;",
        )
        .expect("seed v2 schema");
    }

    let store = FindingsStore::new(&path).expect("open and migrate");
    let rows = store.list_findings(&FindingsQuery::default()).await.expect("list");
    assert!(rows[0].references.is_empty());

    let version: u32 = rusqlite::Connection::open(&path)
        .expect("open")
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .expect("version");
    assert_eq!(version, FindingsStore::SCHEMA_VERSION);
    FindingsStore::new(&path).expect("reopen does not re-run the step");
}
