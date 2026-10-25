//! Baseline promotion: devices graduate on coverage (days seen in the last
//! week) and stability (no new flow tuple for two days), never on row counts.

use std::path::{Path, PathBuf};

use ion_drift_storage::behavior::{DeviceObservation, DeviceProfile};
use ion_drift_storage::BehaviorStore;
use tempfile::tempdir;

const MAC: &str = "00:00:5E:00:53:01";
const DAY: i64 = 86400;
const HOUR: i64 = 3600;

fn db_path() -> PathBuf {
    tempdir().expect("tempdir").keep().join("behavior.db")
}

fn now() -> i64 {
    BehaviorStore::now_unix_pub()
}

/// Start of the current UTC day: observations placed just after it always
/// fall in today's bucket.
fn today_start() -> i64 {
    now() / DAY * DAY
}

fn exec(path: &Path, statement: &str, params: impl rusqlite::Params) {
    rusqlite::Connection::open(path)
        .expect("open behavior.db")
        .execute(statement, params)
        .expect("statement");
}

fn count(path: &Path, statement: &str) -> i64 {
    rusqlite::Connection::open(path)
        .expect("open behavior.db")
        .query_row(statement, [MAC], |row| row.get(0))
        .expect("count")
}

/// Pretend `days` have passed since enrollment by shifting the profile's
/// clock fields together, which keeps the "already extended" relation intact.
fn advance_days(path: &Path, days: i64) {
    exec(
        path,
        "UPDATE device_profiles SET first_seen = first_seen - ?1, learning_until = learning_until - ?1 WHERE mac = ?2",
        rusqlite::params![days * DAY, MAC],
    );
}

fn flow(timestamp: i64, port: i64) -> DeviceObservation {
    DeviceObservation {
        mac: MAC.to_string(),
        timestamp,
        ip: "192.0.2.10".to_string(),
        vlan: 99,
        protocol: "tcp".to_string(),
        dst_port: Some(port),
        dst_subnet: "198.51.100.0/24".to_string(),
        direction: "cross_vlan".to_string(),
        bytes_sent: 200_000,
        bytes_recv: 4_000,
        connection_count: 1,
    }
}

/// One observation per hour on port 554, from `hours` hours before `t0` up to one hour before it.
fn hourly(t0: i64, hours: i64) -> Vec<DeviceObservation> {
    (1..=hours).map(|h| flow(t0 - h * HOUR, 554)).collect()
}

async fn store_with(path: &Path, observations: &[DeviceObservation]) -> BehaviorStore {
    let store = BehaviorStore::new(path).expect("behavior store");
    store
        .upsert_profile(MAC, Some("cam-1"), Some("Example Cameras"), "192.0.2.10", 99)
        .await
        .expect("upsert profile");
    store.record_observations(observations).await.expect("record observations");
    store
}

async fn profile(store: &BehaviorStore) -> DeviceProfile {
    store.get_profile(MAC).await.expect("get_profile").expect("profile exists")
}

#[tokio::test]
async fn stable_device_fast_tracks_after_three_days() {
    let path = db_path();
    let store = store_with(&path, &hourly(now(), 73)).await;

    store.promote_eligible_devices().await.expect("promote");

    assert_eq!(profile(&store).await.baseline_status, "baselined");
}

#[tokio::test]
async fn graduation_recomputes_baselines() {
    let path = db_path();
    let store = store_with(&path, &hourly(now(), 73)).await;

    store.promote_eligible_devices().await.expect("promote");

    assert!(count(&path, "SELECT COUNT(*) FROM device_baselines WHERE mac = ?1") > 0);
}

#[tokio::test]
async fn covered_but_unstable_device_graduates_when_window_ends() {
    let path = db_path();
    let mut observations = hourly(now(), 7 * 24);
    observations.push(flow(now() - HOUR, 8443)); // a flow first seen an hour ago
    let store = store_with(&path, &observations).await;

    store.promote_eligible_devices().await.expect("promote");
    assert_eq!(profile(&store).await.baseline_status, "learning", "not stable, window open");

    advance_days(&path, 8);
    store.promote_eligible_devices().await.expect("promote");
    assert_eq!(profile(&store).await.baseline_status, "baselined", "window ended with coverage");
}

#[tokio::test]
async fn quiet_device_becomes_sparse_when_window_ends() {
    let path = db_path();
    let t = today_start();
    let store = store_with(&path, &[flow(t + 1, 554), flow(t + 2, 554), flow(t + 3, 554)]).await;

    advance_days(&path, 8);
    store.promote_eligible_devices().await.expect("promote");

    assert_eq!(profile(&store).await.baseline_status, "sparse");
}

#[tokio::test]
async fn partial_coverage_gets_one_extension_then_sparse() {
    let path = db_path();
    let t = today_start();
    let store = store_with(&path, &[flow(t - DAY + 1, 554), flow(t + 1, 554)]).await;

    advance_days(&path, 8);
    store.promote_eligible_devices().await.expect("promote");
    let extended = profile(&store).await;
    assert_eq!(extended.baseline_status, "learning");
    assert!(extended.learning_until > now() + 3 * DAY - 60, "extended by three days");

    advance_days(&path, 4);
    store.promote_eligible_devices().await.expect("promote");
    assert_eq!(profile(&store).await.baseline_status, "sparse", "no second extension");
}

#[tokio::test]
async fn sparse_device_graduates_once_active() {
    let path = db_path();
    let store = store_with(&path, &hourly(now(), 5 * 24)).await;
    exec(
        &path,
        "UPDATE device_profiles SET baseline_status = 'sparse' WHERE mac = ?1",
        [MAC],
    );
    advance_days(&path, 8);

    store.promote_eligible_devices().await.expect("promote");

    assert_eq!(profile(&store).await.baseline_status, "baselined");
}

#[tokio::test]
async fn coverage_is_recorded_on_the_profile() {
    let path = db_path();
    let t0 = now();
    let store = store_with(&path, &hourly(t0, 49)).await;

    store.promote_eligible_devices().await.expect("promote");

    let p = profile(&store).await;
    assert!(p.days_seen >= 3, "49 hourly samples span at least three UTC days, got {}", p.days_seen);
    assert_eq!(p.last_new_flow, Some(t0 - 49 * HOUR));
}

#[tokio::test]
async fn sparse_device_stays_sparse_without_coverage() {
    let path = db_path();
    let t = today_start();
    let store = store_with(&path, &[flow(t + 1, 554)]).await;
    exec(&path, "UPDATE device_profiles SET baseline_status = 'sparse' WHERE mac = ?1", [MAC]);
    advance_days(&path, 8);

    let first = store.promote_eligible_devices().await.expect("promote");
    let after_first = profile(&store).await;
    let second = store.promote_eligible_devices().await.expect("promote again");
    let after_second = profile(&store).await;

    assert_eq!((first, second), ((0, 0), (0, 0)), "a sparse device is not counted as promoted");
    assert_eq!(after_first.baseline_status, "sparse");
    assert_eq!(after_second.baseline_status, "sparse");
    assert_eq!(after_first.learning_until, after_second.learning_until, "no extension for sparse");
}
