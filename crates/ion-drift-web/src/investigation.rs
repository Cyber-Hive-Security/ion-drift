//! Automated investigation engine.
//!
//! When the behavior engine detects an anomaly, the investigation engine
//! automatically gathers context (device profile, destination analysis,
//! behavioral history, firewall correlation) and produces a verdict
//! (benign / routine / suspicious / threat / inconclusive) with a
//! human-readable summary and recommended action.
//!
//! All queries are against local SQLite + in-memory caches.
//! No external API calls in the hot path. Target: <500ms per anomaly.

use std::net::IpAddr;
use std::sync::Arc;

use ion_drift_storage::behavior::{
    BehaviorStore, DeviceAnomaly, DeviceProfile, NewInvestigation, VlanRegistry,
};

use crate::connection_store::ConnectionStore;
use crate::geo::GeoCache;

// ── CDN ASN Detection ───────────────────────────────────────

/// Known CDN / major cloud provider ASNs.
/// Used to classify destinations as benign infrastructure.
const CDN_ASNS: &[u32] = &[
    13335,  // Cloudflare
    20940,  // Akamai
    54113,  // Fastly
    16509,  // Amazon (AWS)
    15169,  // Google
    8075,   // Microsoft
    14618,  // Amazon
    16625,  // Akamai
    32934,  // Facebook/Meta
    46489,  // Twitch
    2906,   // Netflix
    36183,  // Akamai
    21342,  // Akamai
    23454,  // Akamai
    23455,  // Akamai
    34164,  // Akamai
    35994,  // Akamai
    393234, // Cloudflare
    8068,   // Microsoft
    8069,   // Microsoft
    8070,   // Microsoft
    8987,   // Microsoft
    20150,  // Microsoft (Bing)
    36459,  // GitHub
    714,    // Apple
    6185,   // Apple
    63293,  // Apple
    396982, // Google (Cloud)
    19527,  // Google
    16550,  // Google
    22577,  // Akamai
    26008,  // Akamai
];

/// Well-known "roaming" protocols that don't indicate unusual behavior.
const ROAMING_PORTS: &[i64] = &[
    53,   // DNS
    67,   // DHCP server
    68,   // DHCP client
    123,  // NTP
    137,  // NetBIOS name service
    138,  // NetBIOS datagram
    1900, // SSDP / UPnP
    3478, // STUN (WebRTC, VoIP)
    5353, // mDNS
];

// ── Investigation Engine ────────────────────────────────────

pub struct InvestigationEngine {
    behavior_store: Arc<BehaviorStore>,
    connection_store: Arc<ConnectionStore>,
    geo_cache: Arc<GeoCache>,
}

impl InvestigationEngine {
    pub fn new(
        behavior_store: Arc<BehaviorStore>,
        connection_store: Arc<ConnectionStore>,
        geo_cache: Arc<GeoCache>,
    ) -> Self {
        Self {
            behavior_store,
            connection_store,
            geo_cache,
        }
    }

    /// Run the full investigation pipeline for a single anomaly.
    /// Returns the investigation record ready for storage.
    pub async fn investigate(&self, anomaly_id: i64) -> Result<NewInvestigation, String> {
        let start = std::time::Instant::now();

        let anomaly = self
            .behavior_store
            .get_anomaly_by_id(anomaly_id)
            .await?
            .ok_or_else(|| format!("anomaly {anomaly_id} not found"))?;

        // Parse details JSON for destination info
        let details: serde_json::Value = anomaly
            .details
            .as_deref()
            .and_then(|d| serde_json::from_str(d).ok())
            .unwrap_or(serde_json::Value::Null);

        // Step 1: Device context
        let device_ctx = self.gather_device_context(&anomaly).await;

        // Step 2: Destination analysis
        let dest_ctx = self.gather_destination_context(&anomaly, &details);

        // Step 3: Behavioral context
        let behavior_ctx = self.gather_behavioral_context(&anomaly).await;

        // Step 4: Traffic pattern
        let traffic_ctx = self.gather_traffic_pattern(&anomaly, &details).await;

        // Step 5: Firewall correlation (already in the anomaly)
        let fw_ctx = FirewallContext {
            rule_id: anomaly.firewall_rule_id.clone(),
            action: details["policy_outcome"]
                .as_str()
                .map(|s| s.to_string()),
            rule_comment: anomaly.firewall_rule_comment.clone(),
            correlation: anomaly.firewall_correlation.clone(),
        };

        // Step 6: Verdict
        let (verdict, action, reason, evidence) = self.determine_verdict(
            &anomaly,
            &device_ctx,
            &dest_ctx,
            &behavior_ctx,
            &traffic_ctx,
            &fw_ctx,
        );

        let summary = self.generate_summary(
            &anomaly, &device_ctx, &dest_ctx, &verdict, &reason,
        );

        let duration_ms = start.elapsed().as_millis() as i64;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Ok(NewInvestigation {
            anomaly_id,
            device_mac: anomaly.mac.clone(),
            device_hostname: device_ctx.hostname.clone(),
            device_manufacturer: device_ctx.manufacturer.clone(),
            device_disposition: device_ctx.disposition.clone(),
            device_first_seen: device_ctx.first_seen,
            device_baseline_status: device_ctx.baseline_status.clone(),
            vlan_id: anomaly.vlan,
            vlan_sensitivity: device_ctx.vlan_sensitivity.clone(),
            dst_ip: dest_ctx.ip.clone(),
            dst_country: dest_ctx.country.clone(),
            dst_city: dest_ctx.city.clone(),
            dst_asn: dest_ctx.asn,
            dst_org: dest_ctx.org.clone(),
            dst_is_cdn: dest_ctx.is_cdn,
            dst_reverse_dns: dest_ctx.reverse_dns.clone(),
            dst_seen_by_device_count: dest_ctx.seen_by_device_count,
            anomaly_type: anomaly.anomaly_type.clone(),
            prior_anomaly_count_24h: behavior_ctx.count_24h,
            prior_anomaly_count_7d: behavior_ctx.count_7d,
            same_pattern_count_24h: behavior_ctx.same_pattern_24h,
            baseline_coverage_pct: behavior_ctx.baseline_coverage_pct,
            current_volume_bytes: traffic_ctx.current_volume,
            baseline_volume_bytes: traffic_ctx.baseline_volume,
            volume_ratio: traffic_ctx.volume_ratio,
            unique_destinations_1h: traffic_ctx.unique_destinations,
            unique_ports_1h: traffic_ctx.unique_ports,
            other_devices_same_dest: Some(dest_ctx.seen_by_device_count),
            firewall_rule_id: fw_ctx.rule_id,
            firewall_action: fw_ctx.action,
            firewall_rule_comment: fw_ctx.rule_comment,
            firewall_correlation: fw_ctx.correlation,
            verdict,
            recommended_action: action,
            reason,
            summary,
            evidence_chain: Some(serde_json::to_string(&evidence).unwrap_or_default()),
            investigated_at: now,
            duration_ms,
        })
    }
}

// ── Context Structs ─────────────────────────────────────────

struct DeviceContext {
    hostname: Option<String>,
    manufacturer: Option<String>,
    disposition: Option<String>,
    first_seen: i64,
    baseline_status: Option<String>,
    vlan_sensitivity: Option<String>,
    is_learning: bool,
}

struct DestinationContext {
    ip: Option<String>,
    country: Option<String>,
    city: Option<String>,
    asn: Option<i64>,
    org: Option<String>,
    is_cdn: bool,
    reverse_dns: Option<String>,
    seen_by_device_count: i64,
    is_flagged_country: bool,
}

struct BehavioralContext {
    count_24h: i64,
    count_7d: i64,
    same_pattern_24h: i64,
    baseline_coverage_pct: Option<f64>,
}

struct TrafficContext {
    current_volume: Option<i64>,
    baseline_volume: Option<i64>,
    volume_ratio: Option<f64>,
    unique_destinations: Option<i64>,
    unique_ports: Option<i64>,
}

struct FirewallContext {
    rule_id: Option<String>,
    action: Option<String>,
    rule_comment: Option<String>,
    correlation: Option<String>,
}

// ── Evidence Chain ──────────────────────────────────────────

#[derive(serde::Serialize)]
struct EvidenceStep {
    check: String,
    result: String,
    passed: bool,
}

// ── Gather Methods ──────────────────────────────────────────

impl InvestigationEngine {
    async fn gather_device_context(&self, anomaly: &DeviceAnomaly) -> DeviceContext {
        let profile = self
            .behavior_store
            .get_profile(&anomaly.mac)
            .await
            .ok()
            .flatten();

        let disposition = match &profile {
            Some(_p) => {
                // Check switch store for disposition — but we don't have switch_store here.
                // Use what we can infer from the profile.
                None
            }
            None => None,
        };

        let vlan_sensitivity = None; // Will be set later from registry if needed

        match profile {
            Some(p) => DeviceContext {
                hostname: p.hostname,
                manufacturer: p.manufacturer,
                disposition,
                first_seen: p.first_seen,
                baseline_status: Some(p.baseline_status.clone()),
                vlan_sensitivity,
                is_learning: p.baseline_status == "learning",
            },
            None => DeviceContext {
                hostname: None,
                manufacturer: None,
                disposition: None,
                first_seen: 0,
                baseline_status: None,
                vlan_sensitivity,
                is_learning: true,
            },
        }
    }

    fn gather_destination_context(
        &self,
        anomaly: &DeviceAnomaly,
        details: &serde_json::Value,
    ) -> DestinationContext {
        // Extract destination IP from anomaly details
        let dst_ip = details["dst_ip"]
            .as_str()
            .or_else(|| details["dst_subnet"].as_str())
            .map(|s| {
                // Strip CIDR suffix if present
                s.split('/').next().unwrap_or(s).to_string()
            });

        let (country, city, asn_num, org, is_cdn) = if let Some(ref ip_str) = dst_ip {
            if let Some(geo) = self.geo_cache.lookup_cached(ip_str) {
                let asn_num = geo
                    .asn
                    .as_ref()
                    .and_then(|s| s.strip_prefix("AS"))
                    .and_then(|s| s.parse::<u32>().ok());
                let is_cdn = asn_num.map_or(false, |n| CDN_ASNS.contains(&n));
                (
                    Some(geo.country_code),
                    geo.city,
                    asn_num.map(|n| n as i64),
                    geo.org,
                    is_cdn,
                )
            } else {
                (None, None, None, None, false)
            }
        } else {
            (None, None, None, None, false)
        };

        // Check if destination is in a flagged/monitored country
        let is_flagged_country = country
            .as_deref()
            .map(|c| self.geo_cache.get_monitored_regions().contains(&c.to_uppercase()))
            .unwrap_or(false);

        // Count how many other devices talk to this destination
        let seen_by_count = dst_ip
            .as_deref()
            .map(|ip| {
                self.connection_store
                    .count_devices_to_destination(ip, 7)
                    .unwrap_or(0)
            })
            .unwrap_or(0);

        DestinationContext {
            ip: dst_ip,
            country,
            city,
            asn: asn_num,
            org,
            is_cdn,
            reverse_dns: None, // Could look up from connection_history if needed
            seen_by_device_count: seen_by_count,
            is_flagged_country,
        }
    }

    async fn gather_behavioral_context(
        &self,
        anomaly: &DeviceAnomaly,
    ) -> BehavioralContext {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let count_24h = self
            .behavior_store
            .count_anomalies_since(&anomaly.mac, now - 86400)
            .await
            .unwrap_or(0);

        let count_7d = self
            .behavior_store
            .count_anomalies_since(&anomaly.mac, now - 7 * 86400)
            .await
            .unwrap_or(0);

        let same_pattern_24h = self
            .behavior_store
            .count_same_pattern_anomalies(&anomaly.mac, &anomaly.anomaly_type, now - 86400)
            .await
            .unwrap_or(0);

        let coverage = self
            .behavior_store
            .baseline_coverage(&anomaly.mac)
            .await
            .ok()
            .map(|(baselines, flows)| {
                if flows > 0 {
                    (baselines as f64 / flows as f64 * 100.0).min(100.0)
                } else {
                    0.0
                }
            });

        BehavioralContext {
            count_24h,
            count_7d,
            same_pattern_24h,
            baseline_coverage_pct: coverage,
        }
    }

    async fn gather_traffic_pattern(
        &self,
        anomaly: &DeviceAnomaly,
        details: &serde_json::Value,
    ) -> TrafficContext {
        // Volume data from the anomaly details (for volume_spike type)
        let current_volume = details["projected_hourly"]
            .as_f64()
            .map(|v| v as i64);
        let baseline_volume = details["baseline_max"]
            .as_f64()
            .map(|v| v as i64);
        let volume_ratio = match (current_volume, baseline_volume) {
            (Some(cur), Some(base)) if base > 0 => Some(cur as f64 / base as f64),
            _ => None,
        };

        let unique_dests = self
            .behavior_store
            .count_unique_destinations(&anomaly.mac, 3600)
            .await
            .ok();

        let unique_ports = self
            .behavior_store
            .count_unique_ports(&anomaly.mac, 3600)
            .await
            .ok();

        TrafficContext {
            current_volume,
            baseline_volume,
            volume_ratio,
            unique_destinations: unique_dests,
            unique_ports,
        }
    }
}

// ── Verdict Determination ───────────────────────────────────

impl InvestigationEngine {
    fn determine_verdict(
        &self,
        anomaly: &DeviceAnomaly,
        device: &DeviceContext,
        dest: &DestinationContext,
        behavior: &BehavioralContext,
        traffic: &TrafficContext,
        fw: &FirewallContext,
    ) -> (String, String, String, Vec<EvidenceStep>) {
        let mut evidence = Vec::new();
        let source_zone = self.extract_zone(&anomaly.details, "source_zone");
        let dst_port = self.extract_dst_port(&anomaly.details);

        // Rule 1: Flagged device — always suspicious
        if device.disposition.as_deref() == Some("flagged") {
            evidence.push(EvidenceStep {
                check: "Device disposition".into(),
                result: "Device was previously flagged by operator".into(),
                passed: true,
            });
            return (
                "suspicious".into(),
                "escalate".into(),
                "Device was previously flagged by operator".into(),
                evidence,
            );
        }

        // Rule 2: Blocked inbound from WAN — routine internet noise
        if anomaly.anomaly_type == "blocked_attempt" && source_zone.as_deref() == Some("WAN") {
            evidence.push(EvidenceStep {
                check: "Blocked inbound from WAN".into(),
                result: "Inbound scan blocked by firewall — normal internet noise".into(),
                passed: true,
            });
            return (
                "routine".into(),
                "no_action".into(),
                "Inbound scan blocked by firewall — normal internet noise".into(),
                evidence,
            );
        }

        // Rule 3: Blocked internal traffic with expected deny rule
        if anomaly.anomaly_type == "blocked_attempt"
            && fw.correlation.as_deref() == Some("expected_deny")
        {
            let rule_comment = fw
                .rule_comment
                .as_deref()
                .unwrap_or("unnamed rule");
            evidence.push(EvidenceStep {
                check: "Expected firewall deny".into(),
                result: format!("Blocked by expected rule: {rule_comment}"),
                passed: true,
            });
            return (
                "benign".into(),
                "no_action".into(),
                format!("Internal traffic blocked by expected firewall rule: {rule_comment}"),
                evidence,
            );
        }

        // Rule 4: New destination to CDN provider
        if anomaly.anomaly_type == "new_destination" && dest.is_cdn {
            let org = dest.org.as_deref().unwrap_or("CDN provider");
            evidence.push(EvidenceStep {
                check: "CDN detection".into(),
                result: format!("Destination is CDN: {org}"),
                passed: true,
            });
            return (
                "benign".into(),
                "no_action".into(),
                format!("New destination is CDN provider ({org})"),
                evidence,
            );
        }

        // Rule 5: New destination seen by many other devices
        if anomaly.anomaly_type == "new_destination" && dest.seen_by_device_count >= 3 {
            let ip = dest.ip.as_deref().unwrap_or("unknown");
            evidence.push(EvidenceStep {
                check: "Destination commonality".into(),
                result: format!(
                    "Destination {ip} seen by {} other devices",
                    dest.seen_by_device_count
                ),
                passed: true,
            });
            return (
                "benign".into(),
                "no_action".into(),
                format!(
                    "Destination {} is common — seen by {} other devices",
                    ip, dest.seen_by_device_count
                ),
                evidence,
            );
        }

        // Rule 6: New port is a roaming/infrastructure protocol
        if anomaly.anomaly_type == "new_port" {
            if let Some(port) = dst_port {
                if ROAMING_PORTS.contains(&port) {
                    evidence.push(EvidenceStep {
                        check: "Roaming protocol".into(),
                        result: format!("Port {port} is a standard infrastructure protocol"),
                        passed: true,
                    });
                    return (
                        "benign".into(),
                        "no_action".into(),
                        format!("Port {port} is a standard infrastructure protocol"),
                        evidence,
                    );
                }
            }
        }

        // Rule 7: Volume spike on sparse baseline — moderate concern
        if anomaly.anomaly_type == "volume_spike" {
            if let Some(ratio) = traffic.volume_ratio {
                evidence.push(EvidenceStep {
                    check: "Volume ratio".into(),
                    result: format!("{ratio:.1}x baseline"),
                    passed: ratio > 5.0,
                });

                if ratio < 5.0 && device.baseline_status.as_deref() == Some("sparse") {
                    return (
                        "routine".into(),
                        "monitor".into(),
                        "Moderate volume increase on device with sparse baseline".into(),
                        evidence,
                    );
                }

                if ratio > 20.0 {
                    return (
                        "suspicious".into(),
                        "investigate".into(),
                        format!("{ratio:.0}x volume spike — significant deviation from baseline"),
                        evidence,
                    );
                }
            }
        }

        // Rule 8: New destination to a flagged country
        if anomaly.anomaly_type == "new_destination" && dest.is_flagged_country {
            let country = dest.country.as_deref().unwrap_or("unknown");
            evidence.push(EvidenceStep {
                check: "Flagged country".into(),
                result: format!("Destination in flagged country: {country}"),
                passed: true,
            });
            return (
                "suspicious".into(),
                "investigate".into(),
                format!("New connection to flagged country: {country}"),
                evidence,
            );
        }

        // Rule 9: Device still in learning period
        if device.is_learning {
            evidence.push(EvidenceStep {
                check: "Learning period".into(),
                result: "Device is still establishing baseline".into(),
                passed: true,
            });
            return (
                "routine".into(),
                "no_action".into(),
                "Device is still in learning period — establishing baseline".into(),
                evidence,
            );
        }

        // Rule 10: Recurring anomaly pattern
        if behavior.same_pattern_24h >= 3 {
            evidence.push(EvidenceStep {
                check: "Repeat pattern".into(),
                result: format!(
                    "{} occurrences of same type in 24h",
                    behavior.same_pattern_24h
                ),
                passed: true,
            });
            return (
                "suspicious".into(),
                "investigate".into(),
                format!(
                    "Recurring anomaly — {} occurrences in 24h",
                    behavior.same_pattern_24h
                ),
                evidence,
            );
        }

        // Default: inconclusive
        evidence.push(EvidenceStep {
            check: "Default".into(),
            result: "No clear determination — manual review recommended".into(),
            passed: false,
        });
        (
            "inconclusive".into(),
            "monitor".into(),
            "No clear determination — manual review recommended".into(),
            evidence,
        )
    }

    fn generate_summary(
        &self,
        anomaly: &DeviceAnomaly,
        device: &DeviceContext,
        dest: &DestinationContext,
        verdict: &str,
        reason: &str,
    ) -> String {
        let device_name = device
            .hostname
            .as_deref()
            .unwrap_or(&anomaly.mac);
        let device_age = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let age_secs = now - device.first_seen;
            if age_secs < 3600 {
                format!("first seen {} min ago", age_secs / 60)
            } else if age_secs < 86400 {
                format!("first seen {} hours ago", age_secs / 3600)
            } else {
                format!("online for {} days", age_secs / 86400)
            }
        };

        let baseline_note = match device.baseline_status.as_deref() {
            Some("learning") => ", no baseline yet".to_string(),
            Some("sparse") => ", sparse baseline".to_string(),
            Some("baselined") => ", fully baselined".to_string(),
            _ => String::new(),
        };

        let dest_desc = if let Some(ref ip) = dest.ip {
            let mut parts = vec![ip.clone()];
            if let Some(ref country) = dest.country {
                parts.push(country.clone());
            }
            if let Some(ref org) = dest.org {
                parts.push(org.clone());
            }
            if dest.is_cdn {
                parts.push("CDN".into());
            }
            parts.join(", ")
        } else {
            "unknown destination".into()
        };

        format!(
            "{device_name} ({device_age}{baseline_note}) — {} to {dest_desc}. {reason}",
            anomaly.anomaly_type.replace('_', " "),
        )
    }

    // ── Helpers ─────────────────────────────────────────────

    fn extract_zone(&self, details: &Option<String>, field: &str) -> Option<String> {
        details
            .as_deref()
            .and_then(|d| serde_json::from_str::<serde_json::Value>(d).ok())
            .and_then(|v| v[field].as_str().map(|s| s.to_string()))
    }

    fn extract_dst_port(&self, details: &Option<String>) -> Option<i64> {
        details
            .as_deref()
            .and_then(|d| serde_json::from_str::<serde_json::Value>(d).ok())
            .and_then(|v| v["dst_port"].as_i64())
    }
}
