//! Background task that computes per-port rate baselines from port metrics.
//!
//! Runs every 5 minutes, computing current rx/tx rates from the 2 most recent
//! port metric samples, then updating the baseline for the current hour-of-week
//! bucket using an exponential moving average.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{Datelike, Timelike, Utc};
use ion_drift_storage::SwitchStore;
use tokio::sync::RwLock;

use crate::device_manager::DeviceManager;

/// Spawn the port baseline computation task.
pub fn spawn_port_baselines(
    switch_store: Arc<SwitchStore>,
    device_manager: Arc<RwLock<DeviceManager>>,
) {
    tokio::spawn(async move {
        // Wait 2 minutes for pollers to populate initial data
        tokio::time::sleep(Duration::from_secs(120)).await;

        let mut interval = tokio::time::interval(Duration::from_secs(300)); // every 5 min
        loop {
            interval.tick().await;
            if let Err(e) = compute_baselines(&switch_store, &device_manager).await {
                tracing::warn!("port baseline computation: {e}");
            }
        }
    });
}

async fn compute_baselines(
    store: &SwitchStore,
    dm: &Arc<RwLock<DeviceManager>>,
) -> anyhow::Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let since = now - 300; // last 5 minutes of port metrics

    // Current hour-of-week: 0-167 (Monday 00:00 UTC = 0, Sunday 23:00 UTC = 167)
    let now_utc = Utc::now();
    let day_of_week = now_utc.weekday().num_days_from_monday(); // 0=Mon, 6=Sun
    let hour_of_week = day_of_week * 24 + now_utc.hour();

    // Get all device IDs
    let device_ids: Vec<String> = {
        let dm_read = dm.read().await;
        dm_read.all_devices().iter().map(|d| d.record.id.clone()).collect()
    };

    let mut total_updates = 0u32;

    for device_id in &device_ids {
        let rows = store.get_port_metrics(device_id, since).await?;
        if rows.is_empty() {
            continue;
        }

        // Group by port_name, keep 2 most recent samples (rows are timestamp DESC)
        let mut by_port: HashMap<String, Vec<(i64, i64, i64)>> = HashMap::new();
        for (port_name, rx_bytes, tx_bytes, ts, _speed, _running, _port_index) in &rows {
            let samples = by_port.entry(port_name.clone()).or_default();
            if samples.len() < 2 {
                samples.push((*ts, *rx_bytes, *tx_bytes));
            }
        }

        for (port_name, samples) in &by_port {
            if samples.len() < 2 {
                continue;
            }
            let (ts_new, rx_new, tx_new) = samples[0];
            let (ts_old, rx_old, tx_old) = samples[1];

            let elapsed = ts_new - ts_old;
            if elapsed <= 0 || elapsed > 600 {
                continue; // skip invalid or stale sample pairs
            }

            let rx_delta = (rx_new - rx_old).max(0) as f64;
            let tx_delta = (tx_new - tx_old).max(0) as f64;
            let elapsed_f = elapsed as f64;

            let rx_bps = (rx_delta * 8.0) / elapsed_f;
            let tx_bps = (tx_delta * 8.0) / elapsed_f;

            // Skip zero-rate samples (port likely down)
            if rx_bps <= 0.0 && tx_bps <= 0.0 {
                continue;
            }

            store
                .update_port_baseline(device_id, port_name, hour_of_week, rx_bps, tx_bps)
                .await?;

            total_updates += 1;
        }
    }

    if total_updates > 0 {
        tracing::debug!(
            updates = total_updates,
            hour_of_week,
            "port baseline computation complete"
        );
    }

    Ok(())
}
