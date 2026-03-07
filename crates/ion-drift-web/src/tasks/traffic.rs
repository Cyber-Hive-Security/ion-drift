use std::sync::Arc;
use std::time::Duration;

use crate::live_traffic::{LiveTrafficBuffer, TrafficSample};

/// Poll WAN traffic counters every 10 seconds for live rates,
/// and every 15 minutes for lifetime totals (SQLite).
pub fn spawn_traffic_poller(
    tracker: Arc<mikrotik_core::TrafficTracker>,
    live_buf: Arc<LiveTrafficBuffer>,
    client: mikrotik_core::MikrotikClient,
) {
    tokio::spawn(async move {
        // Initial poll for lifetime totals
        match tracker.poll(&client).await {
            Ok(t) => tracing::info!(
                "traffic initial poll: rx={}, tx={}", t.rx_bytes, t.tx_bytes
            ),
            Err(e) => tracing::warn!("traffic initial poll failed: {e}"),
        }

        let mut prev_rx: Option<u64> = None;
        let mut prev_tx: Option<u64> = None;
        let mut prev_time: Option<std::time::Instant> = None;
        let mut tick_count: u64 = 0;

        let mut interval = tokio::time::interval(Duration::from_secs(10));
        interval.tick().await; // skip immediate tick
        loop {
            interval.tick().await;
            tick_count += 1;

            // Fetch current interface counters
            let interfaces = match client.interfaces().await {
                Ok(i) => i,
                Err(e) => {
                    tracing::warn!("live traffic poll failed: {e}");
                    continue;
                }
            };

            let wan = interfaces.iter().find(|i| i.name == "1-WAN");
            if let Some(wan) = wan {
                let current_rx = wan.rx_byte.unwrap_or(0);
                let current_tx = wan.tx_byte.unwrap_or(0);
                let now = std::time::Instant::now();

                // Compute per-second rates if we have a previous sample
                if let (Some(prx), Some(ptx), Some(pt)) = (prev_rx, prev_tx, prev_time) {
                    let elapsed = now.duration_since(pt).as_secs_f64();
                    if elapsed > 0.0 && current_rx >= prx && current_tx >= ptx {
                        let rx_bps = ((current_rx - prx) as f64 / elapsed) * 8.0;
                        let tx_bps = ((current_tx - ptx) as f64 / elapsed) * 8.0;
                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64;
                        live_buf
                            .push(TrafficSample {
                                timestamp,
                                rx_bps,
                                tx_bps,
                            })
                            .await;
                    }
                }

                prev_rx = Some(current_rx);
                prev_tx = Some(current_tx);
                prev_time = Some(now);
            }

            // Poll lifetime totals every 90 ticks (~15 minutes at 10s interval)
            if tick_count % 90 == 0 {
                match tracker.poll(&client).await {
                    Ok(t) => tracing::debug!(
                        "traffic poll: rx={}, tx={}", t.rx_bytes, t.tx_bytes
                    ),
                    Err(e) => tracing::warn!("traffic poll failed: {e}"),
                }
            }
        }
    });
}

/// Poll VLAN throughput every 60 seconds, store in SQLite.
pub fn spawn_vlan_metrics_poller(
    store: Arc<ion_drift_storage::MetricsStore>,
    client: mikrotik_core::MikrotikClient,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;

            let vlans = match client.vlan_interfaces().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("VLAN poller: failed to fetch VLANs: {e}");
                    continue;
                }
            };

            // Monitor each VLAN concurrently
            let mut handles = Vec::with_capacity(vlans.len());
            for vlan in &vlans {
                let c = client.clone();
                let name = vlan.name.clone();
                handles.push(tokio::spawn(async move {
                    let result = c.monitor_traffic(&name).await;
                    (name, result)
                }));
            }

            let results = futures::future::join_all(handles).await;
            let mut entries = Vec::new();
            for result in results {
                match result {
                    Ok((name, Ok(samples))) => {
                        let rx = samples.first().and_then(|s| s.rx_bits_per_second).unwrap_or(0);
                        let tx = samples.first().and_then(|s| s.tx_bits_per_second).unwrap_or(0);
                        entries.push((name, rx, tx));
                    }
                    Ok((name, Err(e))) => {
                        tracing::debug!(vlan = %name, error = %e, "VLAN poller: monitor failed");
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "VLAN poller: task panicked");
                    }
                }
            }

            if !entries.is_empty() {
                if let Err(e) = store.record_vlan_metrics(&entries).await {
                    tracing::warn!("VLAN poller: record failed: {e}");
                }
            }
        }
    });
}
