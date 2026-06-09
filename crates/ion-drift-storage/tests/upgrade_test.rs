//! Upgrade-path tests: every deployed database predates version stamping
//! (`user_version == 0`). Opening it with the current code must (a) preserve
//! data, (b) stamp the schema version. And opening data written by a NEWER
//! release must refuse instead of corrupting.

use ion_drift_storage::{BehaviorStore, FindingsStore, MetricsStore, SwitchStore};
use rusqlite::Connection;

fn user_version(path: &std::path::Path) -> u32 {
    let conn = Connection::open(path).expect("open for version check");
    conn.query_row("PRAGMA user_version", [], |r| r.get(0))
        .expect("read user_version")
}

fn set_user_version(path: &std::path::Path, v: u32) {
    let conn = Connection::open(path).expect("open for version set");
    conn.pragma_update(None, "user_version", v).expect("set");
}

/// The real upgrade path for existing installs: a fully-migrated database
/// that has never been stamped (user_version=0) reopens cleanly, keeps its
/// data, and comes out stamped at the current schema version.
#[tokio::test]
async fn switch_pre_versioning_db_upgrades_with_data_intact() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("switch.db");

    // Build the schema with current code, insert a row, then simulate a
    // pre-stamping deployment by resetting user_version to 0.
    {
        let store = SwitchStore::new(&db).expect("initial create");
        store
            .upsert_network_identity(
                "AA:BB:CC:DD:EE:01",
                Some("10.0.0.5"),
                Some("nas"),
                None,
                None,
                None,
                Some(25),
                None,
                None,
                None,
                0.9,
                None,
                None,
                0.0,
            )
            .await
            .expect("insert identity");
    }
    set_user_version(&db, 0);

    // Reopen — the baseline init (idempotent CREATE + guarded ALTERs) reruns,
    // the row survives, and the version is stamped.
    let store = SwitchStore::new(&db).expect("upgrade reopen");
    let identity = store
        .get_identity_by_mac("AA:BB:CC:DD:EE:01")
        .await
        .expect("query")
        .expect("row survived upgrade");
    assert_eq!(identity.best_ip.as_deref(), Some("10.0.0.5"));
    assert_eq!(user_version(&db), SwitchStore::SCHEMA_VERSION);
}

/// Old binary + new data = refuse loudly. This is the direction that
/// corrupts silently without the guard.
#[test]
fn stores_refuse_databases_from_a_newer_release() {
    let dir = tempfile::tempdir().expect("tempdir");

    let switch_db = dir.path().join("switch.db");
    drop(SwitchStore::new(&switch_db).expect("create"));
    set_user_version(&switch_db, SwitchStore::SCHEMA_VERSION + 1);
    let err = match SwitchStore::new(&switch_db) {
        Ok(_) => panic!("must refuse a newer database"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("newer"),
        "error should explain the downgrade: {err}"
    );

    let behavior_db = dir.path().join("behavior.db");
    drop(BehaviorStore::new(&behavior_db).expect("create"));
    set_user_version(&behavior_db, BehaviorStore::SCHEMA_VERSION + 1);
    assert!(BehaviorStore::new(&behavior_db).is_err());

    let findings_db = dir.path().join("findings.db");
    drop(FindingsStore::new(&findings_db).expect("create"));
    set_user_version(&findings_db, FindingsStore::SCHEMA_VERSION + 1);
    assert!(FindingsStore::new(&findings_db).is_err());

    let metrics_db = dir.path().join("metrics.db");
    drop(MetricsStore::new(&metrics_db).expect("create"));
    set_user_version(&metrics_db, MetricsStore::SCHEMA_VERSION + 1);
    assert!(MetricsStore::new(&metrics_db).is_err());
}

/// Fresh databases come out stamped.
#[test]
fn fresh_databases_are_stamped() {
    let dir = tempfile::tempdir().expect("tempdir");

    let switch_db = dir.path().join("switch.db");
    drop(SwitchStore::new(&switch_db).expect("create"));
    assert_eq!(user_version(&switch_db), SwitchStore::SCHEMA_VERSION);

    let behavior_db = dir.path().join("behavior.db");
    drop(BehaviorStore::new(&behavior_db).expect("create"));
    assert_eq!(user_version(&behavior_db), BehaviorStore::SCHEMA_VERSION);

    let findings_db = dir.path().join("findings.db");
    drop(FindingsStore::new(&findings_db).expect("create"));
    assert_eq!(user_version(&findings_db), FindingsStore::SCHEMA_VERSION);

    let metrics_db = dir.path().join("metrics.db");
    drop(MetricsStore::new(&metrics_db).expect("create"));
    assert_eq!(user_version(&metrics_db), MetricsStore::SCHEMA_VERSION);
}
