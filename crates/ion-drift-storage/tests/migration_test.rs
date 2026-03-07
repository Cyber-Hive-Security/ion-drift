use std::path::PathBuf;

use ion_drift_storage::{BehaviorStore, MetricsStore, SwitchStore};
use tempfile::tempdir;

fn db_path(name: &str) -> PathBuf {
    tempdir().expect("tempdir").into_path().join(name)
}

#[test]
fn behavior_store_fresh_and_idempotent() {
    let path = db_path("behavior.db");
    let _s1 = BehaviorStore::new(&path).expect("fresh behavior store");
    let _s2 = BehaviorStore::new(&path).expect("idempotent behavior store reopen");
}

#[tokio::test]
async fn behavior_store_crud_after_migration() {
    let path = db_path("behavior.db");
    let store = BehaviorStore::new(&path).expect("behavior store");
    store
        .upsert_profile("AA:BB:CC:DD:EE:FF", Some("10.0.0.10"), Some(10), None, None)
        .await
        .expect("upsert profile");
    let profile = store
        .get_profile("AA:BB:CC:DD:EE:FF")
        .await
        .expect("get profile")
        .expect("profile exists");
    assert_eq!(profile.current_ip.as_deref(), Some("10.0.0.10"));
}

#[test]
fn metrics_store_fresh_and_idempotent() {
    let path = db_path("metrics.db");
    let _s1 = MetricsStore::new(&path).expect("fresh metrics store");
    let _s2 = MetricsStore::new(&path).expect("idempotent metrics store reopen");
}

#[tokio::test]
async fn metrics_store_crud_after_migration() {
    let path = db_path("metrics.db");
    let store = MetricsStore::new(&path).expect("metrics store");
    store.record(10, 100, 1000).await.expect("record metrics");
    let points = store.query(60).await.expect("query metrics");
    assert!(!points.is_empty());
}

#[test]
fn switch_store_fresh_and_idempotent() {
    let path = db_path("switch.db");
    let _s1 = SwitchStore::new(&path).expect("fresh switch store");
    let _s2 = SwitchStore::new(&path).expect("idempotent switch store reopen");
}

#[tokio::test]
async fn switch_store_crud_after_migration() {
    let path = db_path("switch.db");
    let store = SwitchStore::new(&path).expect("switch store");
    store
        .record_port_metrics(
            "sw1",
            &[ion_drift_storage::switch::PortMetricEntry {
                port_name: "ether1".into(),
                rx_bytes: 100,
                tx_bytes: 200,
                rx_packets: 10,
                tx_packets: 20,
                speed: Some("1Gbps".into()),
                running: true,
            }],
        )
        .await
        .expect("record metrics");
    let points = store
        .get_port_metrics("sw1", 300)
        .await
        .expect("get port metrics");
    assert!(!points.is_empty());
}

#[test]
fn behavior_store_upgrade_adds_confidence_column() {
    let path = db_path("behavior_upgrade.db");
    let conn = rusqlite::Connection::open(&path).expect("open old db");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS device_anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            anomaly_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            details TEXT,
            vlan INTEGER NOT NULL,
            firewall_correlation REAL,
            firewall_rule_id TEXT,
            firewall_rule_comment TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            resolved_at INTEGER,
            resolved_by TEXT
        );",
    )
    .expect("seed old schema");
    drop(conn);

    let _store = BehaviorStore::new(&path).expect("migration should succeed");
    let conn = rusqlite::Connection::open(&path).expect("reopen");
    let mut stmt = conn
        .prepare("PRAGMA table_info(device_anomalies)")
        .expect("pragma table_info");
    let cols: Vec<String> = stmt
        .query_map([], |row| row.get(1))
        .expect("query cols")
        .filter_map(Result::ok)
        .collect();
    assert!(cols.iter().any(|c| c == "confidence"));
}
