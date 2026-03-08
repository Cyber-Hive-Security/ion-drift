use ion_drift_storage::behavior::VlanRegistry;
use ion_drift_web::connection_store::{ConnectionStore, HistoryFilters, PollConnection};
use ion_drift_web::geo::GeoCache;

#[test]
fn connection_store_fresh_and_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("connections.db");
    let _s1 = ConnectionStore::new(&db).expect("fresh store");
    let _s2 = ConnectionStore::new(&db).expect("idempotent reopen");
}

#[test]
fn connection_store_crud_after_migration() {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn_db = dir.path().join("connections.db");
    let geo_db = dir.path().join("geo.db");

    let store = ConnectionStore::new(&conn_db).expect("connection store");
    let geo = GeoCache::new(&geo_db, None, vec![]).expect("geo cache");
    let registry = VlanRegistry::default();

    let inserted = store
        .upsert_from_poll(
            &PollConnection {
                conntrack_id: "abc123".into(),
                protocol: "tcp".into(),
                src_ip: "10.0.0.10".into(),
                dst_ip: "1.1.1.1".into(),
                dst_port: Some(443),
                src_mac: Some("AA:BB:CC:DD:EE:FF".into()),
                tcp_state: Some("established".into()),
                bytes_tx: 1000,
                bytes_rx: 2000,
            },
            &geo,
            &registry,
        )
        .expect("insert");
    assert!(inserted);

    let page = store
        .query_history(&HistoryFilters {
            page: Some(1),
            per_page: Some(20),
            ..Default::default()
        })
        .expect("query history");
    assert!(!page.items.is_empty());
}
