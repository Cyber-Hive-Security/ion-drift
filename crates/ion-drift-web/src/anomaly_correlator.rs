//! Anomaly correlator — cross-references port flow anomalies with device behavior anomalies.
//!
//! Runs every 60 seconds (after 5-minute startup delay). Creates `anomaly_links` records
//! that bridge the two independent detection systems.

use std::sync::Arc;
use std::time::Duration;

use ion_drift_storage::behavior::{BehaviorStore, NewAnomaly, VlanRegistry};
use tokio::sync::RwLock;

use crate::connection_store::{ConnectionStore, FlowClassification, NewAnomalyLink};

/// Spawn the anomaly correlator background task.
pub fn spawn_anomaly_correlator(
    connection_store: Arc<ConnectionStore>,
    behavior_store: Arc<BehaviorStore>,
    vlan_registry: Arc<RwLock<VlanRegistry>>,
) {
    tokio::spawn(async move {
        // Wait 5 minutes for behavior collector + baselines to have initial data
        tokio::time::sleep(Duration::from_secs(300)).await;
        tracing::info!("anomaly correlator starting");

        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;

            let registry = vlan_registry.read().await.clone();
            match run_correlation(&connection_store, &behavior_store, &registry).await {
                Ok((port_links, device_links)) => {
                    if port_links > 0 || device_links > 0 {
                        tracing::info!(
                            "anomaly correlator: created {port_links} port→device links, \
                             {device_links} device→port links"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("anomaly correlator failed: {e}");
                }
            }
        }
    });
}

/// Run one correlation cycle. Returns (port_to_device_links, device_to_port_links).
async fn run_correlation(
    conn_store: &ConnectionStore,
    behavior_store: &BehaviorStore,
    registry: &VlanRegistry,
) -> anyhow::Result<(usize, usize)> {
    let port_links = correlate_port_to_device(conn_store, behavior_store, registry).await?;
    let device_links = correlate_device_to_port(conn_store, behavior_store).await?;
    auto_resolve_links(conn_store, behavior_store).await?;
    Ok((port_links, device_links))
}

/// Port → Device: for each anomalous port flow, find the devices responsible.
async fn correlate_port_to_device(
    conn_store: &ConnectionStore,
    behavior_store: &BehaviorStore,
    registry: &VlanRegistry,
) -> anyhow::Result<usize> {
    let mut total_links = 0;

    for direction in &["outbound", "inbound", "internal"] {
        let summary = conn_store.classified_port_summary(1, direction)?;

        for flow in &summary.flows {
            if matches!(flow.classification, FlowClassification::Normal) {
                continue;
            }

            let classification_str = match flow.classification {
                FlowClassification::NewPort => "new_port",
                FlowClassification::VolumeSpike => "volume_spike",
                FlowClassification::SourceAnomaly => "source_anomaly",
                _ => continue,
            };

            // The involved_devices are already queried in classified_port_summary
            for device in &flow.involved_devices {
                // Check if link already exists
                if conn_store.has_existing_link(
                    &flow.protocol,
                    flow.dst_port,
                    direction,
                    &device.mac,
                )? {
                    continue;
                }

                // Check behavior.db for a matching device anomaly
                let behavior_anomaly_id = find_matching_behavior_anomaly(
                    behavior_store,
                    &device.mac,
                    &flow.protocol,
                    flow.dst_port,
                    classification_str,
                )
                .await;

                let correlated = behavior_anomaly_id.is_some();
                let source = if correlated { "both" } else { "port_flow" };

                // Determine severity based on correlation rules
                let device_count = flow.involved_devices.len();
                let severity = escalated_severity(
                    classification_str,
                    correlated,
                    !flow.days_in_baseline > 0,
                    device_count,
                    device.vlan.as_deref(),
                    registry,
                );

                conn_store.insert_anomaly_link(&NewAnomalyLink {
                    port_anomaly_type: classification_str.to_string(),
                    flow_direction: direction.to_string(),
                    protocol: flow.protocol.clone(),
                    dst_port: flow.dst_port,
                    device_mac: device.mac.clone(),
                    device_ip: device.ip.clone(),
                    device_vlan: device.vlan.clone(),
                    device_hostname: device.hostname.clone(),
                    behavior_anomaly_id,
                    correlated,
                    source: source.to_string(),
                    severity: severity.to_string(),
                    device_bytes: device.bytes,
                    device_connections: device.connections,
                    port_is_baselined: flow.days_in_baseline > 0,
                    port_days_in_baseline: flow.days_in_baseline,
                })?;

                total_links += 1;

                // If no behavior anomaly exists, create one from port flow data
                if !correlated {
                    let vlan = device
                        .vlan
                        .as_deref()
                        .and_then(|v| v.strip_prefix("VLAN "))
                        .and_then(|v| v.split(':').next())
                        .and_then(|v| v.trim().parse::<i64>().ok())
                        .unwrap_or(0);

                    let _ = behavior_store
                        .record_anomaly(&NewAnomaly {
                            mac: device.mac.clone(),
                            anomaly_type: classification_str.to_string(),
                            severity: severity.to_string(),
                            confidence: 0.6, // port flow correlation — moderate confidence
                            description: format!(
                                "{} detected at network level: {} {}/{}",
                                classification_str.replace('_', " "),
                                flow.protocol,
                                flow.dst_port,
                                direction,
                            ),
                            details: Some(
                                serde_json::json!({
                                    "source": "port_flow",
                                    "src_ip": device.ip,
                                    "src_hostname": device.hostname,
                                    "protocol": flow.protocol,
                                    "dst_port": flow.dst_port,
                                    "direction": direction,
                                    "device_bytes": device.bytes,
                                    "device_connections": device.connections,
                                    "network_total_bytes": flow.total_bytes,
                                    "total_devices_on_port": device_count,
                                })
                                .to_string(),
                            ),
                            vlan,
                            firewall_correlation: None,
                            firewall_rule_id: None,
                            firewall_rule_comment: None,
                        })
                        .await;
                }
            }
        }
    }

    Ok(total_links)
}

/// Device → Port: for each recent device anomaly, add port flow context.
async fn correlate_device_to_port(
    conn_store: &ConnectionStore,
    behavior_store: &BehaviorStore,
) -> anyhow::Result<usize> {
    let mut total_links = 0;

    // Get recent pending device anomalies of relevant types
    let anomalies = behavior_store
        .get_anomalies(Some("pending"), None, None, Some(200))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    for anomaly in &anomalies {
        if anomaly.anomaly_type != "new_port" && anomaly.anomaly_type != "volume_spike" {
            continue;
        }

        // Extract port from anomaly details JSON
        let (protocol, dst_port) = match extract_port_from_details(&anomaly.details) {
            Some(p) => p,
            None => continue,
        };

        // Determine direction from anomaly details
        let direction = extract_direction_from_details(&anomaly.details)
            .unwrap_or_else(|| "outbound".to_string());

        // Check if link already exists for this device+port
        if conn_store.has_existing_link(&protocol, dst_port, &direction, &anomaly.mac)? {
            continue;
        }

        // Look up port in port_flow_baseline
        let port_context = conn_store.get_port_flow_context(&protocol, dst_port)?;
        let (port_is_baselined, port_days) = match &port_context {
            Some(ctx) => (ctx.port_is_baselined, ctx.port_days_in_baseline),
            None => (false, 0),
        };

        // Check if this port is also flagged as anomalous at network level
        let network_anomalous = !port_is_baselined;
        let correlated = network_anomalous;

        let severity = if correlated {
            "critical" // Both device and network flagged
        } else {
            "info" // Device new to a well-established port
        };

        conn_store.insert_anomaly_link(&NewAnomalyLink {
            port_anomaly_type: anomaly.anomaly_type.clone(),
            flow_direction: direction,
            protocol,
            dst_port,
            device_mac: anomaly.mac.clone(),
            device_ip: String::new(), // May not be available from anomaly details
            device_vlan: anomaly.vlan.to_string().into(),
            device_hostname: None,
            behavior_anomaly_id: Some(anomaly.id),
            correlated,
            source: "behavior".to_string(),
            severity: severity.to_string(),
            device_bytes: 0,
            device_connections: 0,
            port_is_baselined,
            port_days_in_baseline: port_days,
        })?;

        total_links += 1;
    }

    Ok(total_links)
}

/// Auto-resolve anomaly links when the underlying anomalies are resolved.
async fn auto_resolve_links(
    conn_store: &ConnectionStore,
    behavior_store: &BehaviorStore,
) -> anyhow::Result<()> {
    let links = conn_store.get_unresolved_links()?;

    for link in &links {
        // If link has a behavior anomaly ID, check if it's been resolved
        if let Some(anomaly_id) = link.behavior_anomaly_id {
            // Check if the behavior anomaly is still pending
            let is_resolved = behavior_store
                .get_anomalies(Some("pending"), None, None, Some(10000))
                .await
                .unwrap_or_default()
                .iter()
                .all(|a| a.id != anomaly_id);

            if is_resolved {
                conn_store.resolve_link(link.id, "auto")?;
            }
        }

        // Auto-resolve links older than 7 days
        if let Ok(created) = chrono_like_age_seconds(&link.created_at) {
            if created > 7 * 86400 {
                conn_store.resolve_link(link.id, "auto")?;
            }
        }
    }

    Ok(())
}

/// Find a matching behavior anomaly for a device+port combination.
async fn find_matching_behavior_anomaly(
    behavior_store: &BehaviorStore,
    mac: &str,
    protocol: &str,
    dst_port: i64,
    anomaly_type: &str,
) -> Option<i64> {
    let anomalies = behavior_store
        .get_anomalies_by_mac(mac)
        .await
        .ok()?;

    // Look for a pending anomaly matching this port
    for anomaly in &anomalies {
        if anomaly.status != "pending" {
            continue;
        }
        if anomaly.anomaly_type != anomaly_type && anomaly.anomaly_type != "new_port" {
            continue;
        }

        // Check if the anomaly details reference the same port
        if let Some(ref details) = anomaly.details {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(details) {
                let detail_port = json.get("dst_port").and_then(|v| v.as_i64());
                let detail_proto = json.get("protocol").and_then(|v| v.as_str());

                if detail_port == Some(dst_port)
                    && detail_proto.map(|p| p == protocol).unwrap_or(false)
                {
                    return Some(anomaly.id);
                }
            }
        }
    }
    None
}

/// Extract protocol and port from anomaly details JSON.
fn extract_port_from_details(details: &Option<String>) -> Option<(String, i64)> {
    let details_str = details.as_deref()?;
    let json: serde_json::Value = serde_json::from_str(details_str).ok()?;
    let protocol = json.get("protocol")?.as_str()?.to_string();
    let dst_port = json.get("dst_port")?.as_i64()?;
    Some((protocol, dst_port))
}

/// Extract direction from anomaly details JSON.
fn extract_direction_from_details(details: &Option<String>) -> Option<String> {
    let details_str = details.as_deref()?;
    let json: serde_json::Value = serde_json::from_str(details_str).ok()?;
    json.get("direction")?.as_str().map(|s| s.to_string())
}

/// Determine severity based on correlation rules.
fn escalated_severity(
    classification: &str,
    correlated: bool,
    port_is_baselined: bool,
    device_count: usize,
    device_vlan: Option<&str>,
    registry: &VlanRegistry,
) -> &'static str {
    // Multiple devices on a new port = critical (lateral movement pattern)
    if classification == "new_port" && !port_is_baselined && device_count > 1 {
        return "critical";
    }
    // Correlated: both engines flagged independently
    if correlated && classification == "new_port" {
        return "critical";
    }
    if correlated && classification == "volume_spike" {
        return "critical";
    }
    // Single device on new port
    if classification == "new_port" && !port_is_baselined {
        // Use VLAN sensitivity for single-device new port
        if let Some(vlan_str) = device_vlan {
            let vlan_num = vlan_str
                .strip_prefix("VLAN ")
                .and_then(|v| v.split(':').next())
                .and_then(|v| v.trim().parse::<u16>().ok())
                .unwrap_or(0);
            return registry.anomaly_severity(vlan_num, "new_port");
        }
        return "warning";
    }
    // Port is baselined, device is new to it — low concern
    if port_is_baselined {
        return "info";
    }
    "warning"
}

/// Approximate seconds since an ISO 8601 timestamp.
fn chrono_like_age_seconds(iso: &str) -> Result<i64, ()> {
    // Parse "2026-02-24T12:34:56Z" → unix timestamp
    let parts: Vec<&str> = iso.split('T').collect();
    if parts.len() != 2 {
        return Err(());
    }
    let date_parts: Vec<i64> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();
    let time_str = parts[1].trim_end_matches('Z');
    let time_parts: Vec<i64> = time_str.split(':').filter_map(|p| p.parse().ok()).collect();
    if date_parts.len() != 3 || time_parts.len() != 3 {
        return Err(());
    }

    // Simplified: just use the day difference as an approximation
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Rough epoch calculation (not accounting for leap years, good enough for 7-day threshold)
    let y = date_parts[0];
    let m = date_parts[1];
    let d = date_parts[2];
    let days = (y - 1970) * 365 + (y - 1969) / 4 + month_days(m) + d - 1;
    let ts = days * 86400 + time_parts[0] * 3600 + time_parts[1] * 60 + time_parts[2];
    Ok(now - ts)
}

fn month_days(month: i64) -> i64 {
    const CUMULATIVE: [i64; 13] = [0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    if month >= 1 && month <= 12 {
        CUMULATIVE[month as usize]
    } else {
        0
    }
}
