use std::sync::Arc;
use std::time::Duration;

use mikrotik_core::resources::firewall::FilterRule;
use tokio::sync::RwLock;

use crate::behavior_engine;
use crate::connection_store;
use crate::geo;
use crate::investigation::InvestigationEngine;
use crate::oui;

/// Collect device observations, detect anomalies, and detect blocked attempts every 60s.
/// After detection, runs the investigation engine on any new uninvestigated anomalies.
/// 3-minute startup delay to let the server stabilize.
pub fn spawn_behavior_collector(
    store: Arc<ion_drift_storage::BehaviorStore>,
    client: mikrotik_core::MikrotikClient,
    oui_db: Arc<oui::OuiDb>,
    geo_cache: Arc<geo::GeoCache>,
    connection_store: Arc<connection_store::ConnectionStore>,
    firewall_cache: Arc<RwLock<(Vec<FilterRule>, std::time::Instant)>>,
    vlan_registry: Arc<RwLock<ion_drift_storage::behavior::VlanRegistry>>,
) {
    tokio::spawn(async move {
        // Wait 3 minutes before first collection
        tokio::time::sleep(Duration::from_secs(180)).await;
        tracing::info!("behavior collector starting");

        let spike_candidates = behavior_engine::SpikeCandidates::new();
        let investigation_engine = Arc::new(InvestigationEngine::new(
            store.clone(),
            connection_store,
            geo_cache.clone(),
            vlan_registry.clone(),
        ));
        let mut cycle_count: u64 = 0;

        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cycle_count += 1;

            // Snapshot the current VlanRegistry for this cycle
            let registry = vlan_registry.read().await.clone();

            // Refresh firewall rules cache
            behavior_engine::refresh_firewall_cache(&client, &firewall_cache).await;

            // Collect observations
            match behavior_engine::collect_observations(&client, &store, &oui_db, &registry).await {
                Ok(count) => {
                    tracing::debug!("behavior: collected {count} observations");
                }
                Err(e) => {
                    tracing::warn!("behavior: observation collection failed: {e}");
                    continue;
                }
            }

            // Detect anomalies (with firewall rule correlation)
            let fw_rules = firewall_cache.read().await.0.clone();
            match behavior_engine::detect_anomalies(&store, &spike_candidates, &registry, &fw_rules, &geo_cache).await {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!("behavior: detected {count} anomalies");
                    }
                }
                Err(e) => tracing::warn!("behavior: anomaly detection failed: {e}"),
            }

            // Detect blocked attempts
            match behavior_engine::detect_blocked_attempts(&client, &store, &oui_db, &geo_cache, &registry).await
            {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!("behavior: detected {count} blocked attempts");
                    }
                }
                Err(e) => tracing::warn!("behavior: blocked attempt detection failed: {e}"),
            }

            // Run investigation engine on any new uninvestigated anomalies
            let cycle_start = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            // Look back 5 minutes to catch any we missed
            let since = cycle_start - 300;
            match store.get_uninvestigated_anomaly_ids(since).await {
                Ok(ids) => {
                    if !ids.is_empty() {
                        let count = ids.len();
                        let engine = investigation_engine.clone();
                        let store_ref = store.clone();
                        tokio::spawn(async move {
                            let mut investigated = 0;
                            for id in ids {
                                match engine.investigate(id).await {
                                    Ok(inv) => {
                                        if let Err(e) = store_ref.record_investigation(&inv).await {
                                            tracing::warn!("investigation: failed to store for anomaly {id}: {e}");
                                        } else {
                                            investigated += 1;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("investigation: failed for anomaly {id}: {e}");
                                    }
                                }
                            }
                            if investigated > 0 {
                                tracing::info!("investigation: completed {investigated}/{count} investigations");
                            }
                        });
                    }
                }
                Err(e) => tracing::warn!("investigation: failed to query uninvestigated anomalies: {e}"),
            }

            let _ = &spike_candidates; // placeholder for future spike candidate tracking

            // Promote eligible devices every 10 minutes (10 × 60s cycles)
            if cycle_count % 10 == 0 {
                match store.promote_eligible_devices().await {
                    Ok((baselined, sparse)) => {
                        if baselined > 0 || sparse > 0 {
                            tracing::info!("behavior: promoted {baselined} to baselined, {sparse} to sparse");
                        }
                    }
                    Err(e) => tracing::warn!("behavior: device promotion failed: {e}"),
                }
            }
        }
    });
}

/// Recompute all device baselines nightly at 3 AM and prune old observations.
/// Also runs once at startup (after a 5-minute delay) to promote any devices
/// whose learning period elapsed while the server was down.
pub fn spawn_behavior_maintenance(
    store: Arc<ion_drift_storage::BehaviorStore>,
    connection_store: Arc<connection_store::ConnectionStore>,
    switch_store: Arc<ion_drift_storage::SwitchStore>,
    vlan_registry: Arc<RwLock<ion_drift_storage::behavior::VlanRegistry>>,
) {
    tokio::spawn(async move {
        // Check if maintenance ran recently (within 6 hours) — skip startup run if so
        tokio::time::sleep(Duration::from_secs(300)).await;
        let should_run = match store.get_metadata("last_maintenance").await {
            Ok(Some(ts)) => {
                let last: u64 = ts.parse().unwrap_or(0);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let age = now.saturating_sub(last);
                if age < 6 * 3600 {
                    tracing::info!("behavior maintenance: last ran {}h ago, skipping startup run", age / 3600);
                    false
                } else {
                    true
                }
            }
            _ => true,
        };
        if should_run {
            run_behavior_maintenance(&store, &connection_store, &switch_store, &vlan_registry).await;
        }

        loop {
            // Sleep until next 3 AM local time
            let sleep_secs = secs_until_hour(3);
            tracing::info!("behavior maintenance: next run in {sleep_secs}s (~{:.1}h)", sleep_secs as f64 / 3600.0);
            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;

            run_behavior_maintenance(&store, &connection_store, &switch_store, &vlan_registry).await;
        }
    });
}

async fn run_behavior_maintenance(
    store: &ion_drift_storage::BehaviorStore,
    connection_store: &connection_store::ConnectionStore,
    switch_store: &ion_drift_storage::SwitchStore,
    vlan_registry: &RwLock<ion_drift_storage::behavior::VlanRegistry>,
) {
    // Promote devices whose learning period has elapsed
    match store.promote_eligible_devices().await {
        Ok((baselined, sparse)) => {
            if baselined > 0 || sparse > 0 {
                tracing::info!("behavior: promoted {baselined} to baselined, {sparse} to sparse");
            }
        }
        Err(e) => tracing::warn!("behavior: device promotion failed: {e}"),
    }

    tracing::info!("behavior maintenance: recomputing baselines");
    match store.recompute_all_baselines(7 * 86400).await {
        Ok(count) => tracing::info!("behavior: recomputed baselines for {count} devices"),
        Err(e) => tracing::warn!("behavior: baseline recompute failed: {e}"),
    }

    match store.prune_observations(30 * 86400).await {
        Ok(count) => tracing::info!("behavior: pruned {count} old observations"),
        Err(e) => tracing::warn!("behavior: observation prune failed: {e}"),
    }

    // Auto-resolve stale anomalies
    let registry = vlan_registry.read().await;
    match store.auto_resolve_stale(&registry).await {
        Ok(count) => {
            if count > 0 {
                tracing::info!("behavior: auto-resolved {count} stale anomalies");
            }
        }
        Err(e) => tracing::warn!("behavior: auto-resolve failed: {e}"),
    }

    // Compute port flow baselines for Sankey anomaly detection
    tracing::info!("computing port flow baselines");
    match connection_store.compute_port_flow_baselines() {
        Ok(count) => tracing::info!("port flow baselines: computed {count} baselines"),
        Err(e) => tracing::warn!("port flow baseline computation failed: {e}"),
    }

    // Classify devices by traffic patterns
    classify_traffic_patterns(store, switch_store).await;

    // Persist maintenance watermark
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Err(e) = store.set_metadata("last_maintenance", &now.to_string()).await {
        tracing::warn!("failed to persist maintenance watermark: {e}");
    }
}

/// Compute seconds until the next occurrence of `target_hour` (0-23) in local time.
fn secs_until_hour(target_hour: u32) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    // Determine local UTC offset by comparing libc localtime with UTC
    let local_offset_secs: i64 = {
        let t = now_secs as libc::time_t;
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        unsafe { libc::localtime_r(&t, &mut tm) };
        tm.tm_gmtoff as i64
    };
    let local_secs = now_secs as i64 + local_offset_secs;
    let secs_into_day = local_secs.rem_euclid(86400) as u64;
    let target_secs = (target_hour as u64) * 3600;
    let diff = if target_secs > secs_into_day {
        target_secs - secs_into_day
    } else {
        86400 - secs_into_day + target_secs
    };
    diff.max(60) // minimum 60s to avoid tight loops
}

/// Classify devices by their observed traffic patterns.
///
/// Uses heuristic rules on behavioral observations (dominant ports, bandwidth patterns)
/// to infer device types. Only updates identities where the new confidence exceeds
/// the existing device_type_confidence and the identity is not human-confirmed.
async fn classify_traffic_patterns(
    behavior_store: &ion_drift_storage::BehaviorStore,
    switch_store: &ion_drift_storage::SwitchStore,
) {
    let profiles = match behavior_store.get_all_profiles().await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("traffic classifier: failed to get profiles: {e}");
            return;
        }
    };

    let mut classified = 0u32;

    for profile in &profiles {
        let mac = &profile.mac;

        // Get observations for this device (last 7 days)
        let observations = match behavior_store.get_observations(mac, 7 * 86400).await {
            Ok(obs) => obs,
            Err(_) => continue,
        };

        if observations.is_empty() {
            continue;
        }

        // Aggregate port usage across observations
        let mut port_counts: std::collections::HashMap<i64, u32> = std::collections::HashMap::new();
        let mut total_upload: u64 = 0;
        let mut total_download: u64 = 0;
        let mut total_connections: u64 = 0;

        for obs in &observations {
            if let Some(port) = obs.dst_port {
                *port_counts.entry(port).or_default() += 1;
            }
            total_upload += obs.bytes_sent as u64;
            total_download += obs.bytes_recv as u64;
            total_connections += obs.connection_count as u64;
        }

        // Apply classification rules
        let has_port = |p: i64| port_counts.contains_key(&p);
        let port_dominant = |p: i64| {
            let total: u32 = port_counts.values().sum();
            if total == 0 { return false; }
            port_counts.get(&p).copied().unwrap_or(0) as f64 / total as f64 > 0.3
        };

        let (device_type, confidence, rules): (Option<&str>, f64, Vec<&str>) = if
            (has_port(554) || port_dominant(554)) && total_upload > total_download
        {
            (Some("camera"), 0.8, vec!["port_554_rtsp", "high_upload_ratio"])
        } else if has_port(9100) || has_port(631) {
            let low_traffic = total_connections < 100;
            if low_traffic {
                (Some("printer"), 0.8, vec!["printer_ports", "low_traffic"])
            } else {
                (Some("printer"), 0.75, vec!["printer_ports"])
            }
        } else if has_port(32400) {
            (Some("media_server"), 0.8, vec!["port_32400_plex"])
        } else if has_port(8883) || has_port(1883) {
            (Some("smart_home"), 0.75, vec!["mqtt_ports"])
        } else if port_counts.len() <= 3
            && (has_port(53) || has_port(443) || has_port(80))
            && total_connections < 500
        {
            (Some("phone"), 0.7, vec!["limited_port_diversity", "low_connections"])
        } else if port_counts.len() > 15 && total_connections > 5000 {
            (Some("computer"), 0.7, vec!["high_port_diversity", "high_connections"])
        } else if has_port(22) && has_port(443) && total_connections > 1000 {
            (Some("server"), 0.75, vec!["ssh_https_ports", "high_connections"])
        } else {
            (None, 0.0, vec![])
        };

        if let Some(dt) = device_type {
            let evidence = serde_json::json!({
                "rules_matched": rules,
                "observation_count": observations.len(),
                "window_days": 7,
                "unique_ports": port_counts.len(),
                "total_connections": total_connections,
            });

            // Store classification
            let _ = switch_store.upsert_traffic_classification(
                mac,
                dt,
                confidence,
                &evidence.to_string(),
            ).await;

            // Update identity (confidence hierarchy enforced by upsert)
            let _ = switch_store.upsert_network_identity(
                mac,
                None, None, None, None, None, None, None, None, None,
                0.0, // don't update base confidence
                Some(dt),
                Some("traffic_pattern"),
                confidence,
            ).await;

            classified += 1;
        }
    }

    if classified > 0 {
        tracing::info!("traffic classifier: classified {classified} devices");
    }
}

/// Auto-resolve stale anomalies every hour based on per-VLAN timeout rules.
pub fn spawn_behavior_auto_classifier(
    store: Arc<ion_drift_storage::BehaviorStore>,
    vlan_registry: Arc<RwLock<ion_drift_storage::behavior::VlanRegistry>>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            let registry = vlan_registry.read().await;
            match store.auto_resolve_stale(&registry).await {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!("behavior: auto-resolved {count} stale anomalies");
                    }
                }
                Err(e) => tracing::warn!("behavior: auto-resolve failed: {e}"),
            }
        }
    });
}
