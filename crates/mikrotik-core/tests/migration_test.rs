use mikrotik_core::TrafficTracker;

#[test]
fn traffic_tracker_fresh_and_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("traffic.db");
    let _t1 = TrafficTracker::new(&path, "1-WAN").expect("fresh tracker");
    let _t2 = TrafficTracker::new(&path, "1-WAN").expect("idempotent tracker reopen");
}

#[tokio::test]
async fn traffic_tracker_crud_after_migration() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("traffic.db");
    let tracker = TrafficTracker::new(&path, "1-WAN").expect("tracker");
    let totals = tracker.get_totals().await.expect("totals");
    assert_eq!(totals.interface, "1-WAN");
}
