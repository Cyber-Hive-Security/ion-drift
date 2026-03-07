use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::geo;
use crate::log_parser;
use crate::oui;

/// Poll system resources every 60 seconds, store CPU/memory metrics.
/// Prune data older than 7 days every hour.
pub fn spawn_metrics_poller(
    store: Arc<ion_drift_storage::MetricsStore>,
    client: mikrotik_core::MikrotikClient,
) {
    tokio::spawn(async move {
        let mut tick_count: u64 = 0;
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            tick_count += 1;

            match client.system_resources().await {
                Ok(res) => {
                    let memory_used = res.total_memory - res.free_memory;
                    if let Err(e) = store
                        .record(res.cpu_load, memory_used, res.total_memory)
                        .await
                    {
                        tracing::warn!("metrics record failed: {e}");
                    }
                }
                Err(e) => tracing::warn!("metrics poll failed: {e}"),
            }

            // Cleanup all tables every 60 ticks (every hour)
            if tick_count % 60 == 0 {
                if let Err(e) = store.cleanup(7 * 86400).await {
                    tracing::warn!("metrics cleanup failed: {e}");
                }
            }
        }
    });
}

/// Poll firewall drop counters every 60 seconds, store totals in SQLite.
pub fn spawn_drops_poller(
    store: Arc<ion_drift_storage::MetricsStore>,
    client: mikrotik_core::MikrotikClient,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;

            let rules = match client.firewall_filter_rules().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("drops poller: failed to fetch rules: {e}");
                    continue;
                }
            };

            let (total_packets, total_bytes) = rules
                .iter()
                .filter(|r| r.action == "drop")
                .fold((0u64, 0u64), |(p, b), r| {
                    (p + r.packets.unwrap_or(0), b + r.bytes.unwrap_or(0))
                });

            if let Err(e) = store.record_drops(total_packets, total_bytes).await {
                tracing::warn!("drops poller: record failed: {e}");
            }
        }
    });
}

/// Poll connection tracking summary every 60 seconds, store in SQLite.
pub fn spawn_connection_metrics_poller(
    store: Arc<ion_drift_storage::MetricsStore>,
    client: mikrotik_core::MikrotikClient,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;

            let connections = match client.firewall_connections(".id,protocol").await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("connection poller: failed to fetch connections: {e}");
                    continue;
                }
            };

            let mut tcp = 0u32;
            let mut udp = 0u32;
            let mut other = 0u32;
            for c in &connections {
                match c.protocol.as_deref() {
                    Some("6") | Some("tcp") => tcp += 1,
                    Some("17") | Some("udp") => udp += 1,
                    _ => other += 1,
                }
            }
            let total = connections.len() as u32;

            if let Err(e) = store.record_connections(total, tcp, udp, other).await {
                tracing::warn!("connection poller: record failed: {e}");
            }
        }
    });
}

/// Aggregate log statistics every hour, store roll-ups in SQLite.
pub fn spawn_log_aggregation(
    store: Arc<ion_drift_storage::MetricsStore>,
    client: mikrotik_core::MikrotikClient,
    geo_cache: Arc<geo::GeoCache>,
    oui_db: Arc<oui::OuiDb>,
) {
    tokio::spawn(async move {
        // Wait 2 minutes before first aggregation (let server stabilize)
        tokio::time::sleep(Duration::from_secs(120)).await;

        loop {
            let period_end = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let period_start = period_end - 3600;

            match client.log_entries().await {
                Ok(raw_entries) => {
                    let entries: Vec<_> = raw_entries
                        .iter()
                        .map(|e| log_parser::parse_log_entry(e, &geo_cache, &oui_db))
                        .collect();

                    let total_entries = entries.len() as u32;
                    let mut drop_count = 0u32;
                    let mut accept_count = 0u32;
                    let mut src_counts: HashMap<String, u32> = HashMap::new();
                    let mut port_counts: HashMap<u32, u32> = HashMap::new();
                    let mut iface_counts: HashMap<String, u32> = HashMap::new();

                    for entry in &entries {
                        if let Some(ref parsed) = entry.parsed {
                            match parsed.action.as_deref() {
                                Some("drop") => {
                                    drop_count += 1;
                                    if let Some(ref ip) = parsed.src_ip {
                                        *src_counts.entry(ip.clone()).or_default() += 1;
                                    }
                                    if let Some(port) = parsed.dst_port {
                                        *port_counts.entry(port as u32).or_default() += 1;
                                    }
                                    if let Some(ref iface) = parsed.in_interface {
                                        *iface_counts.entry(iface.clone()).or_default() += 1;
                                    }
                                }
                                Some("accept") => accept_count += 1,
                                _ => {}
                            }
                        }
                    }

                    let top_src = src_counts
                        .iter()
                        .max_by_key(|(_, c)| *c)
                        .map(|(ip, c)| (ip.clone(), *c));
                    let top_port = port_counts
                        .iter()
                        .max_by_key(|(_, c)| *c)
                        .map(|(p, c)| (*p, *c));

                    let drops_by_interface =
                        serde_json::to_string(&iface_counts).unwrap_or_else(|_| "{}".into());

                    if let Err(e) = store
                        .record_log_aggregate(
                            period_start,
                            period_end,
                            total_entries,
                            drop_count,
                            accept_count,
                            top_src.as_ref().map(|(ip, _)| ip.as_str()),
                            top_src.as_ref().map(|(_, c)| *c).unwrap_or(0),
                            top_port.as_ref().map(|(p, _)| *p),
                            top_port.as_ref().map(|(_, c)| *c).unwrap_or(0),
                            &drops_by_interface,
                        )
                        .await
                    {
                        tracing::warn!("log aggregation: record failed: {e}");
                    } else {
                        tracing::info!(
                            "log aggregation: recorded {} entries, {} drops, {} accepts",
                            total_entries,
                            drop_count,
                            accept_count,
                        );
                    }
                }
                Err(e) => tracing::warn!("log aggregation: failed to fetch logs: {e}"),
            }

            // Sleep for 1 hour
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
}
