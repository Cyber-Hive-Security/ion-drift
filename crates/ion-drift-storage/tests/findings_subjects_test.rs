//! Findings name what they are about through `subjects`; legacy `device_macs`
//! fold into endpoint subjects at write time and on upgrade.

use std::path::PathBuf;

use ion_drift_module_api::{FindingEvidence, FindingSeverity, FindingSubject, FindingV1};
use ion_drift_storage::findings::FindingsQuery;
use ion_drift_storage::FindingsStore;
use tempfile::tempdir;

const DEVICE_ID: &str = "switch-7";
const MAC: &str = "00:00:5E:00:53:01";

fn db_path() -> PathBuf {
    tempdir().expect("tempdir").keep().join("findings.db")
}

fn finding(subjects: Vec<FindingSubject>, device_macs: Vec<String>) -> FindingV1 {
    FindingV1 {
        finding_id: "f-1".to_string(),
        title: "title".to_string(),
        narrative: "narrative".to_string(),
        severity: FindingSeverity::Medium,
        category: "test".to_string(),
        recommended_actions: vec![],
        evidence: vec![FindingEvidence::Anomaly { anomaly_id: 1 }],
        subjects,
        device_macs,
        timestamp_unix: 1_700_000_000,
        metadata: None,
    }
}

#[tokio::test]
async fn subjects_round_trip_and_legacy_macs_fold_in() {
    let store = FindingsStore::new(&db_path()).expect("findings store");
    let f = finding(vec![FindingSubject::Device(DEVICE_ID.into())], vec![MAC.into()]);
    store.upsert_finding("advisory", &f, None, None).await.expect("upsert");

    let rows = store.list_findings(&FindingsQuery::default()).await.expect("list");
    assert_eq!(
        rows[0].subjects,
        vec![
            FindingSubject::Device(DEVICE_ID.into()),
            FindingSubject::Endpoint(MAC.into()),
        ]
    );
    assert_eq!(rows[0].device_macs, vec![MAC.to_string()], "legacy field still served");
}

#[tokio::test]
async fn v1_database_backfills_subjects_from_device_macs() {
    let path = db_path();
    {
        // A findings.db as 0.5.5 wrote it: no subjects column, one row with a MAC.
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
                resolution_note TEXT, UNIQUE(module_name, finding_id));
             INSERT INTO findings (module_name, finding_id, title, narrative, severity, category,
                recommended_actions, evidence, device_macs, timestamp, received_at)
             VALUES ('m', 'old', 't', 'n', 'low', 'c', '[]', '[]',
                '[\"00:00:5E:00:53:01\"]', 1, 1);
             PRAGMA user_version = 1;",
        )
        .expect("seed v1 schema");
    }

    let store = FindingsStore::new(&path).expect("open and migrate");
    let rows = store.list_findings(&FindingsQuery::default()).await.expect("list");
    assert_eq!(rows[0].subjects, vec![FindingSubject::Endpoint(MAC.into())]);

    let version: u32 = rusqlite::Connection::open(&path)
        .expect("open")
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .expect("version");
    assert_eq!(version, 2);
    FindingsStore::new(&path).expect("reopen does not re-run the step");
}
