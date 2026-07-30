//! Alerting engine — evaluates alert rules, enforces cooldowns, delivers notifications.
//!
//! Phase 1–4: anomaly_critical, anomaly_correlated, device_new, device_flagged, port_violation,
//! anomaly_warning, interface_down, device_offline, dhcp_pool_exhausted, firewall_drop_spike,
//! auth_bruteforce.
//! Delivery: ntfy, webhook, smtp.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

pub use ion_drift_storage::alerting::{AlertRule, AlertHistoryEntry, AlertStatus, DeliveryChannelConfig};
use ion_drift_storage::behavior::VlanRegistry;
use ion_drift_storage::{BehaviorStore, SwitchStore};
use mikrotik_core::resources::log::LogEntry;
use serde::Deserialize;

use crate::connection_store::ConnectionStore;
use crate::router_queue::{Priority, QueuedRequest};
use crate::state::AppState;
use crate::task_supervisor::TaskSupervisor;

struct PendingAlert {
    rule_id: i64,
    event_type: String,
    severity: String,
    subject: String,
    device_mac: Option<String>,
    device_hostname: Option<String>,
    device_ip: Option<String>,
    vlan_id: Option<i64>,
    title: String,
    body: String,
    anomaly_id: Option<i64>,
    delivery_channels: Vec<String>,
    /// Investigation verdict (benign/routine/suspicious/threat/inconclusive), if available.
    investigation_verdict: Option<String>,
    /// Human-readable investigation summary, if available.
    investigation_summary: Option<String>,
}

// ── Alert store helpers (delegating to SwitchStore methods) ────

pub async fn get_alert_rules(store: &SwitchStore) -> Result<Vec<AlertRule>, String> {
    store.get_alert_rules().await
}

pub async fn get_alert_status(store: &SwitchStore) -> Result<AlertStatus, String> {
    store.get_alert_status().await
}

pub async fn get_alert_history(
    store: &SwitchStore,
    limit: i64,
    offset: i64,
) -> Result<Vec<AlertHistoryEntry>, String> {
    store.get_alert_history(limit, offset).await
}

pub async fn clear_alert_history(store: &SwitchStore) -> Result<usize, String> {
    store.clear_alert_history().await
}

pub async fn get_delivery_channels(store: &SwitchStore) -> Result<Vec<DeliveryChannelConfig>, String> {
    store.get_delivery_channels().await
}

// ── Rule CRUD helpers ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateRuleRequest {
    pub name: String,
    pub event_type: String,
    pub enabled: Option<bool>,
    pub severity_filter: Option<String>,
    pub vlan_filter: Option<String>,
    pub disposition_filter: Option<String>,
    pub verdict_filter: Option<String>,
    pub cooldown_seconds: Option<i64>,
    pub delivery_channels: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateRuleRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub severity_filter: Option<String>,
    pub vlan_filter: Option<String>,
    pub disposition_filter: Option<String>,
    pub verdict_filter: Option<String>,
    pub cooldown_seconds: Option<i64>,
    pub delivery_channels: Option<String>,
}

pub async fn create_rule(store: &SwitchStore, req: CreateRuleRequest) -> Result<AlertRule, String> {
    let enabled = req.enabled.unwrap_or(true);
    let cooldown = req.cooldown_seconds.unwrap_or(300);
    let channels = req.delivery_channels.as_deref().unwrap_or(r#"["ntfy"]"#);

    let id = store
        .create_alert_rule(
            &req.name,
            enabled,
            &req.event_type,
            req.severity_filter.as_deref(),
            req.vlan_filter.as_deref(),
            req.disposition_filter.as_deref(),
            req.verdict_filter.as_deref(),
            cooldown,
            channels,
        )
        .await?;

    let rules = store.get_alert_rules().await?;
    rules.into_iter().find(|r| r.id == id).ok_or("rule not found after insert".into())
}

pub async fn update_rule(store: &SwitchStore, id: i64, req: UpdateRuleRequest) -> Result<(), String> {
    store
        .update_alert_rule(
            id,
            req.name.as_deref(),
            req.enabled,
            req.severity_filter.as_deref(),
            req.vlan_filter.as_deref(),
            req.disposition_filter.as_deref(),
            req.verdict_filter.as_deref(),
            req.cooldown_seconds,
            req.delivery_channels.as_deref(),
        )
        .await
}

pub async fn delete_rule(store: &SwitchStore, id: i64) -> Result<(), String> {
    store.delete_alert_rule(id).await
}

// ── State cache helpers ─────────────────────────────────────────

async fn get_state(store: &SwitchStore, key: &str) -> Option<String> {
    store.get_alert_state(key).await
}

async fn set_state(store: &SwitchStore, key: &str, value: &str) {
    store.set_alert_state(key, value).await
}

// ── Cooldown check ──────────────────────────────────────────────

async fn is_cooled_down(store: &SwitchStore, rule_id: i64, subject: &str, cooldown_secs: i64) -> bool {
    store.is_alert_cooled_down(rule_id, subject, cooldown_secs).await
}

async fn update_cooldown(store: &SwitchStore, rule_id: i64, subject: &str) {
    store.update_alert_cooldown(rule_id, subject).await
}

// ── Record alert history ────────────────────────────────────────

async fn record_alert(store: &SwitchStore, alert: &PendingAlert, attempted: &[String], succeeded: &[String]) {
    store
        .record_alert_history(
            alert.rule_id,
            &alert.event_type,
            &alert.severity,
            alert.device_mac.as_deref(),
            alert.device_hostname.as_deref(),
            alert.device_ip.as_deref(),
            alert.vlan_id,
            &alert.title,
            &alert.body,
            &serde_json::to_string(attempted).unwrap_or_default(),
            &serde_json::to_string(succeeded).unwrap_or_default(),
            alert.anomaly_id,
        )
        .await
}

// ── ntfy delivery ───────────────────────────────────────────────

async fn deliver_ntfy(
    http: &reqwest::Client,
    config: &serde_json::Value,
    title: &str,
    body: &str,
    severity: &str,
    ntfy_token: Option<&str>,
) -> Result<(), String> {
    let url = config.get("url").and_then(|v| v.as_str()).unwrap_or("");
    let topic = config.get("topic").and_then(|v| v.as_str()).unwrap_or("");
    let token = ntfy_token.unwrap_or("");

    if url.is_empty() {
        return Err("ntfy server URL not configured".into());
    }
    if topic.is_empty() {
        return Err("ntfy topic not configured".into());
    }

    let priority = match severity {
        "critical" => "5",
        "alert" => "4",
        "warning" => "3",
        _ => "1",
    };

    let mut req = http
        .post(format!("{url}/{topic}"))
        .header("X-Title", title)
        .header("X-Priority", priority)
        .header("X-Tags", "ion-drift")
        .body(body.to_string())
        .timeout(Duration::from_secs(10));

    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let resp = req.send().await.map_err(|e| format!("ntfy request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("ntfy returned {}", resp.status()));
    }
    Ok(())
}

// ── Webhook delivery ────────────────────────────────────────────

async fn deliver_webhook(
    http: &reqwest::Client,
    config: &serde_json::Value,
    title: &str,
    body: &str,
    severity: &str,
    alert: Option<&PendingAlert>,
    webhook_secret: Option<&str>,
) -> Result<(), String> {
    let url = config.get("url").and_then(|v| v.as_str()).unwrap_or("");
    let secret = webhook_secret.unwrap_or("");

    if url.is_empty() {
        return Err("webhook URL not configured".into());
    }

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let payload = serde_json::json!({
        "event_type": alert.map(|a| a.event_type.as_str()).unwrap_or("test"),
        "severity": severity,
        "title": title,
        "body": body,
        "device_mac": alert.and_then(|a| a.device_mac.as_deref()),
        "device_hostname": alert.and_then(|a| a.device_hostname.as_deref()),
        "device_ip": alert.and_then(|a| a.device_ip.as_deref()),
        "vlan_id": alert.and_then(|a| a.vlan_id),
        "fired_at": format!("{now_ts}"),
        "anomaly_id": alert.and_then(|a| a.anomaly_id),
        "investigation": alert.and_then(|a| {
            a.investigation_verdict.as_ref().map(|v| serde_json::json!({
                "verdict": v,
                "summary": a.investigation_summary.as_deref(),
            }))
        }),
    });

    let payload_bytes = serde_json::to_vec(&payload).map_err(|e| format!("json encode: {e}"))?;

    let mut req = http
        .post(url)
        .header("Content-Type", "application/json")
        .body(payload_bytes.clone())
        .timeout(Duration::from_secs(10));

    if !secret.is_empty() {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|e| format!("hmac init: {e}"))?;
        mac.update(&payload_bytes);
        let sig = hex::encode(mac.finalize().into_bytes());
        req = req.header("X-Ion-Drift-Signature", format!("sha256={sig}"));
    }

    let resp = req.send().await.map_err(|e| format!("webhook request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("webhook returned {}", resp.status()));
    }
    Ok(())
}

// ── SMTP delivery ───────────────────────────────────────────────

async fn deliver_smtp(
    config: &serde_json::Value,
    smtp_password: Option<&str>,
    title: &str,
    body: &str,
) -> Result<(), String> {
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

    let host = config.get("host").and_then(|v| v.as_str()).unwrap_or("");
    let port: u16 = config.get("port").and_then(|v| v.as_u64()).unwrap_or(587) as u16;
    let username = config.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let from = config.get("from").and_then(|v| v.as_str()).unwrap_or("");
    let to_arr = config.get("to").and_then(|v| v.as_array());

    if host.is_empty() || from.is_empty() {
        return Err("SMTP host and from address required".into());
    }

    let recipients: Vec<&str> = to_arr
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    if recipients.is_empty() {
        return Err("no SMTP recipients configured".into());
    }

    let password = smtp_password.unwrap_or("");
    if password.is_empty() {
        return Err("SMTP password not configured (store via encrypted secrets)".into());
    }

    // Build message
    let mut email_builder = Message::builder()
        .from(from.parse().map_err(|e| format!("invalid from address: {e}"))?)
        .subject(title);

    for to in &recipients {
        email_builder = email_builder.to(to.parse().map_err(|e| format!("invalid to address '{to}': {e}"))?);
    }

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let full_body = format!("{body}\n\n--\nIon Drift Network Security\n{now_ts}");

    let email = email_builder
        .header(ContentType::TEXT_PLAIN)
        .body(full_body)
        .map_err(|e| format!("email build: {e}"))?;

    // Build transport
    let creds = Credentials::new(username.to_string(), password.to_string());

    let transport = if port == 465 {
        AsyncSmtpTransport::<Tokio1Executor>::relay(host)
            .map_err(|e| format!("smtp relay: {e}"))?
            .port(port)
            .credentials(creds)
            .timeout(Some(Duration::from_secs(15)))
            .build()
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
            .map_err(|e| format!("smtp starttls: {e}"))?
            .port(port)
            .credentials(creds)
            .timeout(Some(Duration::from_secs(15)))
            .build()
    };

    transport.send(email).await.map_err(|e| format!("smtp send: {e}"))?;
    Ok(())
}

// ── Channel config update ───────────────────────────────────────

pub async fn update_channel_config(
    store: &SwitchStore,
    channel: &str,
    enabled: Option<bool>,
    config_json: Option<serde_json::Value>,
) -> Result<(), String> {
    let json_str = config_json
        .map(|cfg| serde_json::to_string(&cfg))
        .transpose()
        .map_err(|e| format!("json encode: {e}"))?;
    store
        .update_delivery_channel(channel, enabled, json_str.as_deref())
        .await
}

/// Send a test notification to a channel.
///
/// `channel_secret` is the decrypted secret for this channel type:
/// SMTP password, ntfy token, or webhook HMAC secret.
pub async fn test_channel(
    http: &reqwest::Client,
    store: &SwitchStore,
    channel: &str,
    channel_secret: Option<&str>,
) -> Result<(), String> {
    let channels = get_delivery_channels(store).await?;
    let config = channels.iter().find(|c| c.channel == channel)
        .ok_or_else(|| format!("unknown channel: {channel}"))?;

    let title = "Ion Drift — Test Alert";
    let body = &format!(
        "This is a test notification from Ion Drift. If you received this, your {channel} delivery channel is configured correctly."
    );

    match channel {
        "ntfy" => deliver_ntfy(http, &config.config_json, title, body, "info", channel_secret).await,
        "webhook" => deliver_webhook(http, &config.config_json, title, body, "info", None, channel_secret).await,
        "smtp" => deliver_smtp(&config.config_json, channel_secret, title, body).await,
        _ => Err(format!("unknown channel '{channel}'")),
    }
}

// ── Alert engine evaluation cycle ───────────────────────────────

/// Resolved secrets for all delivery channels, decrypted from SecretsManager.
struct ChannelSecrets {
    smtp_password: Option<String>,
    ntfy_token: Option<String>,
    webhook_secret: Option<String>,
}

async fn evaluate_cycle(
    state: &AppState,
    http: &reqwest::Client,
    secrets: &ChannelSecrets,
) {
    let switch_store = &state.switch_store;
    let behavior_store = &state.behavior_store;
    let connection_store = &state.connection_store;
    // Load enabled rules
    let rules = match get_alert_rules(switch_store).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("alerting: failed to load rules: {e}");
            return;
        }
    };

    let enabled_rules: Vec<_> = rules.into_iter().filter(|r| r.enabled).collect();
    if enabled_rules.is_empty() {
        return;
    }

    // Load delivery channel configs
    let channels = match get_delivery_channels(switch_store).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("alerting: failed to load channels: {e}");
            return;
        }
    };

    let mut pending_alerts: Vec<PendingAlert> = Vec::new();

    for rule in &enabled_rules {
        match rule.event_type.as_str() {
            "anomaly_critical" | "anomaly_correlated" => {
                collect_anomaly_alerts(switch_store, behavior_store, connection_store, rule, &mut pending_alerts).await;
            }
            "device_new" => {
                collect_new_device_alerts(switch_store, &*state.vlan_registry.read().await, rule, &mut pending_alerts).await;
            }
            "device_flagged" => {
                collect_flagged_device_alerts(switch_store, rule, &mut pending_alerts).await;
            }
            "port_violation" => {
                collect_port_violation_alerts(switch_store, rule, &mut pending_alerts).await;
            }
            "anomaly_warning" => {
                collect_anomaly_warning_alerts(behavior_store, switch_store, rule, &mut pending_alerts).await;
            }
            "interface_down" => {
                collect_interface_down_alerts(switch_store, rule, &mut pending_alerts).await;
            }
            "device_offline" => {
                collect_device_offline_alerts(switch_store, rule, &mut pending_alerts).await;
            }
            "dhcp_pool_exhausted" => {
                collect_dhcp_pool_alerts(state, rule, &mut pending_alerts).await;
            }
            "firewall_drop_spike" => {
                collect_firewall_drop_spike_alerts(state, rule, &mut pending_alerts).await;
            }
            "auth_bruteforce" => {
                collect_auth_bruteforce_alerts(state, rule, &mut pending_alerts).await;
            }
            _ => {}
        }
    }

    // Enrich anomaly alerts with investigation verdicts and filter by verdict_filter
    for alert in &mut pending_alerts {
        if let Some(anomaly_id) = alert.anomaly_id {
            if let Ok(Some(inv)) = behavior_store.get_investigation_by_anomaly(anomaly_id).await {
                // Enrich title and body with verdict
                let verdict_label = inv.verdict.to_uppercase();
                alert.title = format!("[{}] {}", verdict_label, alert.title);
                alert.body = format!(
                    "Verdict: {} — {}\n\n{}",
                    inv.verdict,
                    inv.summary,
                    alert.body,
                );
                alert.investigation_verdict = Some(inv.verdict.clone());
                alert.investigation_summary = Some(inv.summary.clone());
            }
        }
    }

    // Apply verdict_filter: drop alerts whose investigation verdict doesn't match the rule filter
    pending_alerts.retain(|alert| {
        if let Some(rule) = enabled_rules.iter().find(|r| r.id == alert.rule_id) {
            if let Some(ref filter) = rule.verdict_filter {
                // verdict_filter is a comma-separated list of accepted verdicts
                let accepted: Vec<&str> = filter.split(',').map(|s| s.trim()).collect();
                if let Some(ref verdict) = alert.investigation_verdict {
                    return accepted.iter().any(|a| a.eq_ignore_ascii_case(verdict));
                }
                // No verdict yet — keep the alert (investigation may not have run)
            }
        }
        true
    });

    // Deliver alerts
    let mut total_fired = 0;
    for alert in &pending_alerts {
        // Check cooldown
        if !is_cooled_down(switch_store, alert.rule_id, &alert.subject,
            enabled_rules.iter().find(|r| r.id == alert.rule_id)
                .map(|r| r.cooldown_seconds).unwrap_or(300)).await
        {
            continue;
        }

        let mut attempted = Vec::new();
        let mut succeeded = Vec::new();

        for ch_name in &alert.delivery_channels {
            if let Some(ch_config) = channels.iter().find(|c| &c.channel == ch_name && c.enabled) {
                attempted.push(ch_name.clone());
                let result = match ch_name.as_str() {
                    "ntfy" => deliver_ntfy(http, &ch_config.config_json, &alert.title, &alert.body, &alert.severity, secrets.ntfy_token.as_deref()).await,
                    "webhook" => deliver_webhook(http, &ch_config.config_json, &alert.title, &alert.body, &alert.severity, Some(alert), secrets.webhook_secret.as_deref()).await,
                    "smtp" => deliver_smtp(&ch_config.config_json, secrets.smtp_password.as_deref(), &alert.title, &alert.body).await,
                    _ => Err(format!("channel '{ch_name}' not implemented")),
                };
                match result {
                    Ok(()) => {
                        succeeded.push(ch_name.clone());
                        tracing::debug!("alerting: delivered {} via {}", alert.event_type, ch_name);
                    }
                    Err(e) => {
                        tracing::warn!("alerting: {} delivery failed for {}: {e}", ch_name, alert.event_type);
                    }
                }
            }
        }

        record_alert(switch_store, alert, &attempted, &succeeded).await;
        update_cooldown(switch_store, alert.rule_id, &alert.subject).await;
        total_fired += 1;
    }

    // Update engine timestamp
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    set_state(switch_store, "engine:last_check", &now_ts.to_string()).await;

    if total_fired > 0 {
        tracing::info!("alerting: fired {total_fired} alerts");
    }
}

// ── Event collectors ────────────────────────────────────────────

async fn collect_anomaly_alerts(
    switch_store: &SwitchStore,
    behavior_store: &BehaviorStore,
    connection_store: &ConnectionStore,
    rule: &AlertRule,
    alerts: &mut Vec<PendingAlert>,
) {
    let channels = parse_channels(&rule.delivery_channels);

    if rule.event_type == "anomaly_critical" {
        // Check for new critical anomalies since last seen ID
        let last_id_str = get_state(switch_store, "anomaly:last_id").await.unwrap_or_default();
        let last_id: i64 = last_id_str.parse().unwrap_or(0);

        let anomalies = match behavior_store
            .get_anomalies(Some("pending"), Some("critical"), None, None, Some(50))
            .await
        {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("alerting: failed to get anomalies: {e}");
                return;
            }
        };

        let mut max_id = last_id;
        for anomaly in &anomalies {
            if anomaly.id <= last_id {
                continue;
            }
            max_id = max_id.max(anomaly.id);

            let hostname = anomaly.mac.clone(); // fallback
            alerts.push(PendingAlert {
                rule_id: rule.id,
                event_type: "anomaly_critical".into(),
                severity: "critical".into(),
                subject: anomaly.mac.clone(),
                device_mac: Some(anomaly.mac.clone()),
                device_hostname: Some(hostname),
                device_ip: None,
                vlan_id: Some(anomaly.vlan),
                title: format!("Critical Anomaly — {}", anomaly.mac),
                body: anomaly.description.clone(),
                anomaly_id: Some(anomaly.id),
                delivery_channels: channels.clone(),
                investigation_verdict: None,
                investigation_summary: None,
            });
        }

        if max_id > last_id {
            set_state(switch_store, "anomaly:last_id", &max_id.to_string()).await;
        }
    } else if rule.event_type == "anomaly_correlated" {
        // Check for new correlated anomaly links
        let last_id_str = get_state(switch_store, "anomaly_link:last_id").await.unwrap_or_default();
        let last_id: i64 = last_id_str.parse().unwrap_or(0);

        let links = match connection_store.get_unresolved_links() {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!("alerting: failed to get anomaly links: {e}");
                return;
            }
        };

        let mut max_id = last_id;
        for link in &links {
            if link.id <= last_id {
                continue;
            }
            max_id = max_id.max(link.id);

            alerts.push(PendingAlert {
                rule_id: rule.id,
                event_type: "anomaly_correlated".into(),
                severity: "critical".into(),
                subject: link.device_mac.clone(),
                device_mac: Some(link.device_mac.clone()),
                device_hostname: link.device_hostname.clone(),
                device_ip: Some(link.device_ip.clone()),
                vlan_id: None,
                title: format!("Correlated Anomaly — {}", link.device_hostname.as_deref().unwrap_or(&link.device_mac)),
                body: format!(
                    "Both behavioral engine and port flow baseline flagged suspicious activity on port {} {}",
                    link.protocol, link.dst_port
                ),
                anomaly_id: link.behavior_anomaly_id,
                delivery_channels: channels.clone(),
                investigation_verdict: None,
                investigation_summary: None,
            });
        }

        if max_id > last_id {
            set_state(switch_store, "anomaly_link:last_id", &max_id.to_string()).await;
        }
    }
}

async fn collect_new_device_alerts(
    switch_store: &SwitchStore,
    vlan_registry: &VlanRegistry,
    rule: &AlertRule,
    alerts: &mut Vec<PendingAlert>,
) {
    let channels = parse_channels(&rule.delivery_channels);

    // Find devices with first_seen in the last 2 minutes and disposition = 'unknown'
    let rows: Vec<(String, Option<String>, Option<String>, Option<String>, Option<i64>)> = {
        let db = switch_store.db().await;
        let mut stmt = match db.prepare(
            "SELECT mac_address, best_ip, hostname, manufacturer, vlan_id
             FROM network_identities
             WHERE disposition = 'unknown'
               AND first_seen > (strftime('%s', 'now') - 120)",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("alerting: device_new query failed: {e}");
                return;
            }
        };
        match stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                tracing::warn!("alerting: device_new query_map failed: {e}");
                return;
            }
        }
    };

    for (mac, ip, hostname, manufacturer, vlan_id) in rows {
        let mfg = manufacturer.as_deref().unwrap_or("Unknown");
        let ip_str = ip.as_deref().unwrap_or("unknown");
        let vlan_name = vlan_id
            .map(|v| vlan_registry.vlan_name(v))
            .unwrap_or_else(|| "Unknown".to_string());

        alerts.push(PendingAlert {
            rule_id: rule.id,
            event_type: "device_new".into(),
            severity: "info".into(),
            subject: mac.clone(),
            device_mac: Some(mac.clone()),
            device_hostname: hostname.clone(),
            device_ip: ip.clone(),
            vlan_id,
            title: "New Device Detected".into(),
            body: format!(
                "Unknown device appeared on network: {mac} ({mfg}), IP {ip_str}, VLAN {vlan_name}. Review in Identity Manager."
            ),
            anomaly_id: None,
            delivery_channels: channels.clone(),
            investigation_verdict: None,
            investigation_summary: None,
        });
    }
}

async fn collect_flagged_device_alerts(
    switch_store: &SwitchStore,
    rule: &AlertRule,
    alerts: &mut Vec<PendingAlert>,
) {
    let channels = parse_channels(&rule.delivery_channels);

    // Get all flagged devices
    let flagged: Vec<(String, Option<String>, Option<String>, Option<i64>)> = {
        let db = switch_store.db().await;
        let mut stmt = match db.prepare(
            "SELECT mac_address, best_ip, hostname, vlan_id
             FROM network_identities WHERE disposition = 'flagged'",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("alerting: device_flagged query failed: {e}");
                return;
            }
        };
        match stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                tracing::warn!("alerting: device_flagged query_map failed: {e}");
                return;
            }
        }
    };

    for (mac, ip, hostname, vlan_id) in flagged {
        let cache_key = format!("identity:{mac}:disposition");
        let prev = get_state(switch_store, &cache_key).await;

        if prev.as_deref() == Some("flagged") {
            // Already known to be flagged — not a new transition
            continue;
        }

        // New transition to flagged
        set_state(switch_store, &cache_key, "flagged").await;

        // On first engine run (prev is None), don't fire
        if prev.is_none() {
            continue;
        }

        let display = hostname.as_deref().unwrap_or(&mac).to_string();
        let ip_str = ip.as_deref().unwrap_or("unknown").to_string();

        alerts.push(PendingAlert {
            rule_id: rule.id,
            event_type: "device_flagged".into(),
            severity: "warning".into(),
            subject: mac.clone(),
            device_mac: Some(mac),
            device_hostname: hostname,
            device_ip: ip,
            vlan_id,
            title: "Device Flagged".into(),
            body: format!("{display} ({ip_str}) has been marked as flagged. Review in Identity Manager."),
            anomaly_id: None,
            delivery_channels: channels.clone(),
            investigation_verdict: None,
            investigation_summary: None,
        });
    }
}

async fn collect_port_violation_alerts(
    switch_store: &SwitchStore,
    rule: &AlertRule,
    alerts: &mut Vec<PendingAlert>,
) {
    let channels = parse_channels(&rule.delivery_channels);

    let last_id_str = get_state(switch_store, "port_violation:last_id").await.unwrap_or_default();
    let last_id: i64 = last_id_str.parse().unwrap_or(0);

    let violations: Vec<(i64, String, String, String, Option<String>, String)> = {
        let db = switch_store.db().await;
        let mut stmt = match db.prepare(
            "SELECT id, device_id, port_name, expected_mac, actual_mac, violation_type
             FROM port_violations WHERE id > ?1 AND resolved = 0",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("alerting: port_violation query failed: {e}");
                return;
            }
        };
        match stmt.query_map(rusqlite::params![last_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                tracing::warn!("alerting: port_violation query_map failed: {e}");
                return;
            }
        }
    };

    let mut max_id = last_id;
    for (id, device_id, port_name, expected_mac, actual_mac, violation_type) in violations {
        max_id = max_id.max(id);
        let actual = actual_mac.as_deref().unwrap_or("unknown");

        alerts.push(PendingAlert {
            rule_id: rule.id,
            event_type: "port_violation".into(),
            severity: "warning".into(),
            subject: format!("port:{device_id}:{port_name}"),
            device_mac: Some(expected_mac.clone()),
            device_hostname: None,
            device_ip: None,
            vlan_id: None,
            title: "Port Security Violation".into(),
            body: format!(
                "{violation_type} on {device_id} port {port_name}: expected {expected_mac}, found {actual}."
            ),
            anomaly_id: None,
            delivery_channels: channels.clone(),
            investigation_verdict: None,
            investigation_summary: None,
        });
    }

    if max_id > last_id {
        set_state(switch_store, "port_violation:last_id", &max_id.to_string()).await;
    }
}

async fn collect_anomaly_warning_alerts(
    behavior_store: &BehaviorStore,
    switch_store: &SwitchStore,
    rule: &AlertRule,
    alerts: &mut Vec<PendingAlert>,
) {
    let channels = parse_channels(&rule.delivery_channels);

    let last_id_str = get_state(switch_store, "anomaly_warning:last_id").await.unwrap_or_default();
    let last_id: i64 = last_id_str.parse().unwrap_or(0);

    let anomalies = match behavior_store
        .get_anomalies(Some("pending"), Some("warning"), None, None, Some(50))
        .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!("alerting: failed to get warning anomalies: {e}");
            return;
        }
    };

    let mut max_id = last_id;
    for anomaly in &anomalies {
        if anomaly.id <= last_id {
            continue;
        }
        max_id = max_id.max(anomaly.id);

        alerts.push(PendingAlert {
            rule_id: rule.id,
            event_type: "anomaly_warning".into(),
            severity: "warning".into(),
            subject: anomaly.mac.clone(),
            device_mac: Some(anomaly.mac.clone()),
            device_hostname: Some(anomaly.mac.clone()),
            device_ip: None,
            vlan_id: Some(anomaly.vlan),
            title: format!("Warning Anomaly — {}", anomaly.mac),
            body: anomaly.description.clone(),
            anomaly_id: Some(anomaly.id),
            delivery_channels: channels.clone(),
            investigation_verdict: None,
            investigation_summary: None,
        });
    }

    if max_id > last_id {
        set_state(switch_store, "anomaly_warning:last_id", &max_id.to_string()).await;
    }
}

async fn collect_interface_down_alerts(
    switch_store: &SwitchStore,
    rule: &AlertRule,
    alerts: &mut Vec<PendingAlert>,
) {
    let channels = parse_channels(&rule.delivery_channels);

    // Query the most recent port metrics grouped by device+port to detect running → not-running transitions
    let ports: Vec<(String, String, bool)> = {
        let db = switch_store.db().await;
        let mut stmt = match db.prepare(
            "SELECT device_id, port_name, running
             FROM switch_port_metrics
             WHERE timestamp = (
                 SELECT MAX(timestamp) FROM switch_port_metrics AS s2
                 WHERE s2.device_id = switch_port_metrics.device_id
                   AND s2.port_name = switch_port_metrics.port_name
             )",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("alerting: interface_down query failed: {e}");
                return;
            }
        };
        match stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i32>(2)? != 0))
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                tracing::warn!("alerting: interface_down query_map failed: {e}");
                return;
            }
        }
    };

    for (device_id, port_name, running) in ports {
        let cache_key = format!("iface:{device_id}:{port_name}:running");
        let prev = get_state(switch_store, &cache_key).await;

        let new_val = if running { "1" } else { "0" };
        set_state(switch_store, &cache_key, new_val).await;

        // Only alert on transition from running to not-running (prev was "1", now "0")
        if !running && prev.as_deref() == Some("1") {
            alerts.push(PendingAlert {
                rule_id: rule.id,
                event_type: "interface_down".into(),
                severity: "warning".into(),
                subject: format!("iface:{device_id}:{port_name}"),
                device_mac: None,
                device_hostname: Some(device_id.clone()),
                device_ip: None,
                vlan_id: None,
                title: "Interface Down".into(),
                body: format!("Port {port_name} on {device_id} has gone down."),
                anomaly_id: None,
                delivery_channels: channels.clone(),
                investigation_verdict: None,
                investigation_summary: None,
            });
        }
    }
}

async fn collect_device_offline_alerts(
    switch_store: &SwitchStore,
    rule: &AlertRule,
    alerts: &mut Vec<PendingAlert>,
) {
    let channels = parse_channels(&rule.delivery_channels);

    // Check confirmed devices that haven't been seen in > 5 minutes
    let devices: Vec<(String, Option<String>, Option<String>, Option<i64>, i64)> = {
        let db = switch_store.db().await;
        let mut stmt = match db.prepare(
            "SELECT mac_address, best_ip, hostname, vlan_id, last_seen
             FROM network_identities
             WHERE disposition = 'confirmed'",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("alerting: device_offline query failed: {e}");
                return;
            }
        };
        match stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                tracing::warn!("alerting: device_offline query_map failed: {e}");
                return;
            }
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    for (mac, ip, hostname, vlan_id, last_seen) in devices {
        let offline = (now - last_seen) > 300; // 5 min threshold
        let cache_key = format!("device:{mac}:online");
        let prev = get_state(switch_store, &cache_key).await;

        let new_val = if offline { "0" } else { "1" };
        set_state(switch_store, &cache_key, new_val).await;

        // Only alert on transition from online to offline
        if offline && prev.as_deref() == Some("1") {
            let display = hostname.as_deref().unwrap_or(&mac).to_string();
            let ip_str = ip.as_deref().unwrap_or("unknown").to_string();

            alerts.push(PendingAlert {
                rule_id: rule.id,
                event_type: "device_offline".into(),
                severity: "info".into(),
                subject: mac.clone(),
                device_mac: Some(mac),
                device_hostname: hostname,
                device_ip: ip,
                vlan_id,
                title: "Registered Device Offline".into(),
                body: format!("{display} ({ip_str}) has gone offline (not seen for >5 minutes)."),
                anomaly_id: None,
                delivery_channels: channels.clone(),
                investigation_verdict: None,
                investigation_summary: None,
            });
        }
    }
}

async fn collect_dhcp_pool_alerts(state: &AppState, rule: &AlertRule, alerts: &mut Vec<PendingAlert>) {
    use crate::router_queue::{Priority, QueuedRequest};

    let channels = parse_channels(&rule.delivery_channels);

    // Fetch DHCP servers, pools, and leases from the router via queue (High priority for alerts)
    let batch_results = match state.router_queue.submit(
        "alert_engine_dhcp",
        Priority::High,
        vec![
            QueuedRequest::get("ip/dhcp-server"),
            QueuedRequest::get("ip/pool"),
            QueuedRequest::get("ip/dhcp-server/lease"),
        ],
    ).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("alerting: dhcp_pool_exhausted: queue submit failed: {e}");
            return;
        }
    };

    let mut batch_iter = batch_results.into_iter();
    let servers_val = batch_iter.next().unwrap();
    let pools_val = batch_iter.next().unwrap();
    let leases_val = batch_iter.next().unwrap();

    let servers: Vec<mikrotik_core::resources::ip::DhcpServer> = match servers_val.and_then(|v| {
        serde_json::from_value(v).map_err(|e| mikrotik_core::MikrotikError::Deserialize(e.to_string()))
    }) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("alerting: dhcp_pool_exhausted: failed to fetch DHCP servers: {e}");
            return;
        }
    };
    let pools: Vec<mikrotik_core::resources::ip::IpPool> = match pools_val.and_then(|v| {
        serde_json::from_value(v).map_err(|e| mikrotik_core::MikrotikError::Deserialize(e.to_string()))
    }) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("alerting: dhcp_pool_exhausted: failed to fetch IP pools: {e}");
            return;
        }
    };
    let leases: Vec<mikrotik_core::resources::ip::DhcpLease> = match leases_val.and_then(|v| {
        serde_json::from_value(v).map_err(|e| mikrotik_core::MikrotikError::Deserialize(e.to_string()))
    }) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("alerting: dhcp_pool_exhausted: failed to fetch DHCP leases: {e}");
            return;
        }
    };

    // Build a map of pool_name → total capacity from pool ranges
    let mut pool_capacity: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for pool in &pools {
        let mut total = 0u64;
        for range_str in pool.ranges.split(',') {
            let range_str = range_str.trim();
            if let Some((start_s, end_s)) = range_str.split_once('-') {
                if let (Ok(start), Ok(end)) = (
                    start_s.trim().parse::<std::net::Ipv4Addr>(),
                    end_s.trim().parse::<std::net::Ipv4Addr>(),
                ) {
                    let s: u32 = start.into();
                    let e: u32 = end.into();
                    if e >= s {
                        total += (e - s + 1) as u64;
                    }
                }
            }
        }
        if total > 0 {
            pool_capacity.insert(pool.name.clone(), total);
        }
    }

    // Count active leases per DHCP server's address pool
    for server in &servers {
        if server.disabled == Some(true) {
            continue;
        }
        let pool_name = match &server.address_pool {
            Some(p) => p.clone(),
            None => continue,
        };
        let capacity = match pool_capacity.get(&pool_name) {
            Some(&c) => c,
            None => continue,
        };

        // Count bound/active leases for this server
        let active_count = leases.iter().filter(|l| {
            l.server.as_deref() == Some(&server.name)
                && l.status.as_deref() == Some("bound")
        }).count() as u64;

        let utilization = if capacity > 0 { (active_count as f64 / capacity as f64) * 100.0 } else { 0.0 };

        if utilization > 90.0 {
            alerts.push(PendingAlert {
                rule_id: rule.id,
                event_type: "dhcp_pool_exhausted".into(),
                severity: "warning".into(),
                subject: format!("dhcp:{pool_name}"),
                device_mac: None,
                device_hostname: None,
                device_ip: None,
                vlan_id: None,
                title: format!("DHCP Pool Near Exhaustion — {pool_name}"),
                body: format!(
                    "Pool \"{pool_name}\" (server {}) is at {:.0}% capacity ({active_count}/{capacity} leases).",
                    server.name, utilization
                ),
                anomaly_id: None,
                delivery_channels: channels.clone(),
                investigation_verdict: None,
                investigation_summary: None,
            });
        }
    }
}

async fn collect_firewall_drop_spike_alerts(state: &AppState, rule: &AlertRule, alerts: &mut Vec<PendingAlert>) {
    let channels = parse_channels(&rule.delivery_channels);

    // Query the last hour of drop metrics
    let drop_points = match state.metrics_store.query_drops(3600).await {
        Ok(pts) => pts,
        Err(e) => {
            tracing::warn!("alerting: firewall_drop_spike: failed to query drop metrics: {e}");
            return;
        }
    };

    if drop_points.len() < 2 {
        // Not enough data to compare
        return;
    }

    // Compute 1-hour rolling average (all points except the last one)
    let history = &drop_points[..drop_points.len() - 1];
    let avg_rate: f64 = if history.is_empty() {
        0.0
    } else {
        let total_packets: u64 = history.iter().map(|p| p.drop_packets).sum();
        total_packets as f64 / history.len() as f64
    };

    if avg_rate <= 0.0 {
        return;
    }

    // Compare the latest sample against the rolling average
    let latest = &drop_points[drop_points.len() - 1];
    let current_rate = latest.drop_packets as f64;

    if current_rate > 3.0 * avg_rate {
        alerts.push(PendingAlert {
            rule_id: rule.id,
            event_type: "firewall_drop_spike".into(),
            severity: "warning".into(),
            subject: "system:firewall_drop_spike".into(),
            device_mac: None,
            device_hostname: None,
            device_ip: None,
            vlan_id: None,
            title: "Firewall Drop Spike Detected".into(),
            body: format!(
                "Current drop rate ({current_rate:.0} packets) is {:.1}x the 1-hour average ({avg_rate:.0} packets). Possible scan or attack in progress.",
                current_rate / avg_rate
            ),
            anomaly_id: None,
            delivery_channels: channels.clone(),
            investigation_verdict: None,
            investigation_summary: None,
        });
    }
}

// ── Auth brute-force detection (CVE-2026-16347) ─────────────────
//
// RouterOS lacks effective rate-limiting on API/service logins (CVE-2026-16347,
// CWE-307): the per-connection login delay is bypassable via concurrent
// sessions, so the router itself will never stop a credential-guessing run.
// This collector watches the router log ring buffer for `login failure` entries
// and raises alerts on failure bursts. A same-second multi-failure burst from
// one source is the signature of the concurrent-session delay bypass.

/// Alert-state key holding the last processed log `.id` (parsed numeric form).
const AUTH_BF_CURSOR_KEY: &str = "auth_bruteforce:last_log_id";
/// `router_queue` poller id for this collector's `/log` fetch. Every submitter
/// needs its own: the queue keys pending work by poller id and evicts the older
/// batch when two of them collide, which would silently skip a whole cycle.
const AUTH_BF_POLLER_ID: &str = "alerting-auth-bruteforce";
/// New failures from a single (source, service) per cycle to raise a warning.
const AUTH_BF_WARN_THRESHOLD: usize = 5;
/// New failures from a single (source, service) per cycle to raise a critical.
const AUTH_BF_CRIT_THRESHOLD: usize = 15;
/// Low-and-slow: total failures across many sources to raise a distributed alert.
const AUTH_BF_DISTRIBUTED_TOTAL: usize = 15;
/// Low-and-slow: minimum distinct source IPs for the distributed alert.
const AUTH_BF_DISTRIBUTED_SOURCES: usize = 5;
/// Failures sharing one log timestamp (1s resolution) = concurrent-session bypass.
const AUTH_BF_SAME_SECOND_BURST: usize = 3;

/// A single parsed `login failure for user <u> from <ip> via <service>` log entry.
#[derive(Debug, Clone)]
struct LoginFailure {
    user: String,
    /// Absent for console logins (`login failure for user x via console`).
    src_ip: Option<String>,
    service: String,
    /// Raw RouterOS log timestamp string (1-second resolution).
    time: String,
    /// Severity prefix the emitting logging action prepended (e.g. `SYS-ERR:`),
    /// empty when the action sets no prefix. Each configured `/system/logging`
    /// action logs the same event once, so one real failure appears once per
    /// prefix; counting is done per prefix bucket to avoid multiplying counts.
    prefix: String,
}

/// One detected brute-force signal, ready to become a PendingAlert.
#[derive(Debug)]
pub struct BruteforceSignal {
    /// Cooldown subject, e.g. `auth:10.0.0.5:api` or `auth:distributed`.
    pub subject: String,
    pub src_ip: Option<String>,
    /// Display form only — for the distributed signal this is a joined list and
    /// must never be parsed. Use [`BruteforceSignal::services`] for that.
    pub service: String,
    /// Every service the signal covers paired with the failures that landed on
    /// that service *alone*, in sorted order by service. One entry for a
    /// per-source signal, N for a distributed sweep.
    ///
    /// Per-service because [`Self::count`] is a cross-service total for a
    /// sweep. Writing that total onto every service's surface made one stray
    /// api failure alongside a 20-failure ssh sweep look like a 21-event attack
    /// on the api service — reviving, on the wrong surface, the false positive
    /// the advisory surface-scope check exists to stop.
    pub services: Vec<(String, usize)>,
    /// Every distinct source IP the signal covers. Empty for console logins.
    pub sources: Vec<String>,
    pub count: usize,
    pub users: Vec<String>,
    pub severity: &'static str,
    /// Same-second burst observed — the per-connection delay bypass.
    pub delay_bypass: bool,
    pub distributed: bool,
}

impl BruteforceSignal {
    /// The catalog-facing signal id for this observation.
    ///
    /// Ids name a behaviour, never an advisory — the linkage from a signal to
    /// an advisory lives in `advisory_signal` rows loaded from the catalog.
    /// Every value here must appear in [`crate::advisory::signals::EMITTED_SIGNALS`].
    pub fn signal_id(&self) -> &'static str {
        if self.delay_bypass {
            "auth.login_failure_same_second_burst"
        } else if self.distributed {
            "auth.login_failure_distributed"
        } else {
            "auth.login_failure_burst"
        }
    }
}

/// Parse a RouterOS log `.id` (`"*1F4"`) into its numeric form.
fn parse_log_id(id: &str) -> Option<u64> {
    u64::from_str_radix(id.strip_prefix('*')?, 16).ok()
}

/// Parse a `login failure` log message into its components.
///
/// A `/system/logging` action may prepend a prefix, so the real message is
/// `[<prefix>: ]login failure for user <u> [from <ip> ]via <service>`.
///
/// Both separators are matched from the *right*. The username is the one field
/// on the line an attacker chooses, and RouterOS writes it verbatim into the
/// middle of it, so a separator found from the left is a separator the attacker
/// may have supplied. Splitting on the first ` from ` let a username of
/// `admin from 127.0.0.1` donate that loopback address to `src_ip` while the
/// router's real source slid into the tail — and [`is_own_source`] then read the
/// attempt as Drift's own and dropped it before detection. The router appends
/// ` from <ip>` and ` via <service>` at the end of the line, so the last
/// occurrence of each is the real one and no username can reach past it.
fn parse_login_failure(entry: &LogEntry) -> Option<LoginFailure> {
    const MARKER: &str = "login failure for user ";
    let start = entry.message.find(MARKER)?;
    let prefix = entry.message[..start].trim().to_string();
    let rest = &entry.message[start + MARKER.len()..];
    // Two shapes: "<user> from <ip> via <service>" and "<user> via <service>".
    let (head, service) = rest.rsplit_once(" via ")?;
    let (user, src_ip) = match head.rsplit_once(" from ") {
        // Whatever follows the router's own ` from ` is kept verbatim, even
        // when it is not a recognisable address: a recorded source must stay a
        // source. Downgrading an unparseable one to `None` would present it as
        // a console entry, which the unset-`local_source_ip` fallback treats as
        // Drift's own — the same blinding this split exists to close.
        // Well-formedness is judged in `is_own_source`, which parses.
        Some((user, source)) => (user, Some(source.to_string())),
        None => (head, None),
    };
    Some(LoginFailure {
        user: user.to_string(),
        src_ip,
        service: service.trim().to_string(),
        time: entry.time.clone(),
        prefix,
    })
}

/// Collapse the per-logging-action duplicates of the same events.
///
/// Every configured `/system/logging` action logs each event once, so a router
/// with three actions reports one real failure three times, identical except
/// for the action's prefix. Each prefix bucket therefore holds the complete set
/// of real failures; the largest bucket is that set. Picking a bucket (rather
/// than deduplicating by timestamp) keeps genuine same-second concurrent
/// attempts distinct — that burst is the CVE-2026-16347 signature.
fn dedup_logging_actions<'a>(failures: &[&'a LoginFailure]) -> Vec<&'a LoginFailure> {
    let mut by_prefix: BTreeMap<&str, Vec<&'a LoginFailure>> = BTreeMap::new();
    for f in failures {
        by_prefix.entry(f.prefix.as_str()).or_default().push(f);
    }
    by_prefix
        .into_values()
        .max_by_key(|bucket| bucket.len())
        .unwrap_or_default()
}

/// True when a log entry's source address could plausibly be Drift itself.
///
/// With `[router] local_source_ip` configured, only that address counts: Drift
/// always reaches the router over the network, so its own failures always carry
/// a source. Unset, the only sources accepted are "none recorded" (a local
/// console entry) and a real loopback address.
///
/// Every candidate is parsed as an [`IpAddr`] before it is judged, never
/// prefix-matched, and anything that does not parse is never Drift's own.
/// `src_ip` is carved out of a line that embeds an attacker-chosen username, so
/// a textual test on it is a test on attacker input: `ip.starts_with("127.")`
/// accepted `"127.0.0.1 from 10.20.35.99"` — exactly what a username of
/// `admin from 127.0.0.1` produced — and with `router.username` at its default
/// of `admin`, that silently deleted a live attack from detection on a stock
/// configuration. Failing closed here means the worst case is Drift's own stale
/// credential being reported as an attack, not an attack being reported as
/// Drift's own.
fn is_own_source(src_ip: Option<&str>, own_source: Option<&str>) -> bool {
    match (own_source, src_ip) {
        // Configured: a console entry carries no source and Drift never logs in
        // from the console, so it is not Drift's own.
        (Some(_), None) => false,
        (Some(own), Some(ip)) => {
            // Compared as addresses, not as text, so nothing that merely starts
            // with (or contains) the configured value can pass. A configured
            // value that is not an address matches nothing — the safe direction.
            let (Ok(ip), Ok(own)) = (ip.parse::<IpAddr>(), own.parse::<IpAddr>()) else {
                return false;
            };
            ip == own
        }
        (None, None) => true,
        (None, Some(ip)) => ip.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
    }
}

/// Split off the failures produced by Drift's own router credential.
///
/// `MikrotikClient` sends HTTP Basic auth on every request and `router_queue`
/// drains a batch sequentially in tens of milliseconds, so a stale stored
/// password lands several failures inside a single 1-second log timestamp —
/// exactly the shape of the concurrent-session delay bypass. Left in, Drift
/// would report itself as an in-progress attack. The failures are still worth
/// surfacing, just as a broken-integration warning rather than an intrusion,
/// so they are returned separately instead of being dropped silently.
///
/// A failure only counts as Drift's own when the username matches *and* the
/// source is plausibly Drift ([`is_own_source`]). Matching on the username
/// alone would be a detection-killer rather than a false-positive fix:
/// `router.username` defaults to `admin`, so anyone guessing that account from
/// anywhere would have every one of their failures moved out of detection.
/// The comparison is exact for the same reason — RouterOS usernames are
/// case-sensitive, and `Admin` is a different account than `admin`.
///
/// Returns `(kept, own_credential_failures)`.
fn split_own_credential_failures(
    failures: &[LoginFailure],
    own_user: &str,
    own_source: Option<&str>,
) -> (Vec<LoginFailure>, Vec<LoginFailure>) {
    failures
        .iter()
        .cloned()
        .partition(|f| !(f.user == own_user && is_own_source(f.src_ip.as_deref(), own_source)))
}

/// Group failures by (source, service) and emit signals for bursts and
/// distributed (low-and-slow) patterns.
fn detect_bruteforce(failures: &[LoginFailure]) -> Vec<BruteforceSignal> {
    let mut groups: BTreeMap<(String, String), Vec<&LoginFailure>> = BTreeMap::new();
    for f in failures {
        let src = f.src_ip.clone().unwrap_or_else(|| "local".into());
        groups.entry((src, f.service.clone())).or_default().push(f);
    }
    let groups: BTreeMap<(String, String), Vec<&LoginFailure>> = groups
        .into_iter()
        .map(|(k, v)| {
            let deduped = dedup_logging_actions(&v);
            (k, deduped)
        })
        .collect();
    let total_failures: usize = groups.values().map(Vec::len).sum();

    let mut signals = Vec::new();
    for ((src, service), group) in &groups {
        if group.len() < AUTH_BF_WARN_THRESHOLD {
            continue;
        }
        let mut users: Vec<String> = group.iter().map(|f| f.user.clone()).collect();
        users.sort();
        users.dedup();

        // Same-second burst: N failures sharing one 1s-resolution timestamp can
        // only come from concurrent sessions — the CVE-2026-16347 bypass.
        let mut per_second: BTreeMap<&str, usize> = BTreeMap::new();
        for f in group {
            *per_second.entry(f.time.as_str()).or_default() += 1;
        }
        let delay_bypass = per_second.values().any(|&n| n >= AUTH_BF_SAME_SECOND_BURST);

        signals.push(BruteforceSignal {
            subject: format!("auth:{src}:{service}"),
            src_ip: (src != "local").then(|| src.clone()),
            service: service.clone(),
            services: vec![(service.clone(), group.len())],
            sources: if src == "local" { Vec::new() } else { vec![src.clone()] },
            count: group.len(),
            users,
            severity: if group.len() >= AUTH_BF_CRIT_THRESHOLD || delay_bypass {
                "critical"
            } else {
                "warning"
            },
            delay_bypass,
            distributed: false,
        });
    }

    // Low-and-slow sweep: every source stays under the per-source threshold but
    // the aggregate is clearly a coordinated guessing run.
    if signals.is_empty() && total_failures >= AUTH_BF_DISTRIBUTED_TOTAL {
        let deduped: Vec<&LoginFailure> = groups.values().flatten().copied().collect();
        let mut sources: Vec<&str> = deduped
            .iter()
            .filter_map(|f| f.src_ip.as_deref())
            .collect();
        sources.sort();
        sources.dedup();
        if sources.len() >= AUTH_BF_DISTRIBUTED_SOURCES {
            let mut users: Vec<String> = deduped.iter().map(|f| f.user.clone()).collect();
            users.sort();
            users.dedup();
            // Counted per service, not just listed: `count` below is the
            // cross-service total the sweep is judged on, and correlation must
            // not attribute that total to a service that contributed one
            // failure to it. BTreeMap keys keep the order sorted by service.
            let mut per_service: BTreeMap<&str, usize> = BTreeMap::new();
            for f in &deduped {
                *per_service.entry(f.service.as_str()).or_default() += 1;
            }
            signals.push(BruteforceSignal {
                subject: "auth:distributed".into(),
                src_ip: None,
                // `service` stays a human-readable join for the alert body; the
                // machine-readable list rides in `services` so correlation can
                // key on one surface per service instead of a joined blob.
                service: per_service.keys().copied().collect::<Vec<_>>().join(", "),
                services: per_service
                    .iter()
                    .map(|(service, count)| ((*service).to_string(), *count))
                    .collect(),
                sources: sources.iter().map(|s| (*s).to_string()).collect(),
                count: total_failures,
                users,
                severity: "critical",
                delay_bypass: false,
                distributed: true,
            });
        }
    }

    signals
}

fn bruteforce_alert_body(signal: &BruteforceSignal) -> String {
    let mut shown_users = signal.users.clone();
    let extra = shown_users.len().saturating_sub(5);
    shown_users.truncate(5);
    let users_label = if extra > 0 {
        format!("{} (+{extra} more)", shown_users.join(", "))
    } else {
        shown_users.join(", ")
    };

    let mut body = if signal.distributed {
        format!(
            "{} failed login attempts via {} from multiple source IPs since the last check (users tried: {users_label}). Pattern is consistent with a distributed credential-guessing sweep.",
            signal.count, signal.service
        )
    } else {
        format!(
            "{} failed login attempts via {} from {} since the last check (users tried: {users_label}).",
            signal.count,
            signal.service,
            signal.src_ip.as_deref().unwrap_or("local console")
        )
    };

    if signal.delay_bypass {
        body.push_str(
            " Multiple failures within the same second indicate concurrent sessions bypassing the per-connection login delay (CVE-2026-16347).",
        );
    }
    if signal.service.contains("api") {
        body.push_str(
            " RouterOS API auth has no effective rate limiting (CVE-2026-16347, no fixed release); restrict API access with firewall rules and use long random passwords.",
        );
    }
    body
}

/// What a fetched log batch means for the stored cursor.
#[derive(Debug, PartialEq, Eq)]
enum CursorAction {
    /// Leave the stored cursor exactly as it is — nothing was learned about how
    /// far the log has advanced.
    Hold,
    /// Move the cursor to this id and skip detection for this cycle.
    Reset(u64),
    /// Process the entries newer than this id.
    Advance(u64),
}

/// Decide what to do with the stored cursor for one fetched log batch.
///
/// `entries` is `None` when the batch could not be read at all — a failed fetch
/// or a payload that did not deserialize. That says nothing about the log's
/// position, and treating it as an empty buffer is actively harmful: `max_id`
/// becomes 0, which is indistinguishable from a router reboot, so the cursor is
/// rewound to 0 and the *entire* ring buffer is replayed as new on the next
/// cycle — easily reported as a distributed brute force for an attack that
/// ended weeks ago. Only a batch that parsed cleanly and is genuinely empty is
/// a real buffer reset.
fn cursor_action(entries: Option<&[LogEntry]>, stored: Option<u64>) -> CursorAction {
    let Some(entries) = entries else {
        return CursorAction::Hold;
    };
    let max_id = entries.iter().filter_map(|e| parse_log_id(&e.id)).max().unwrap_or(0);
    match stored {
        // First run, or the log buffer reset (router reboot): initialize the
        // cursor without alerting on entries of unknown age.
        None => CursorAction::Reset(max_id),
        Some(c) if c > max_id => CursorAction::Reset(max_id),
        Some(c) => CursorAction::Advance(c),
    }
}

/// Read the router log ring buffer forward from `cursor_key` and return the
/// brute-force signals in the new entries.
///
/// Kept here (rather than in `advisory::exploitation`) because the parsers and
/// thresholds it drives live in this module. Each consumer passes its own
/// cursor key so no consumer can drain entries another one has not seen yet,
/// and its own `poller_id` because `router_queue` keys pending work by that id
/// and evicts the older batch when two submitters collide on it.
pub(crate) async fn scan_auth_signals_with_cursor(
    state: &AppState,
    poller_id: &str,
    cursor_key: &str,
) -> Vec<BruteforceSignal> {
    // Fetch the router log ring buffer through the shared queue.
    let results = match state
        .router_queue
        .submit(poller_id, Priority::Normal, vec![QueuedRequest::get("log")])
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("{poller_id}: auth_bruteforce: log fetch failed: {e}");
            return Vec::new();
        }
    };
    // `None` means "batch unreadable" — see `cursor_action`, which must not
    // confuse that with an empty ring buffer.
    let entries: Option<Vec<LogEntry>> = match results.first() {
        Some(Ok(v)) => match serde_json::from_value::<Vec<LogEntry>>(v.clone()) {
            Ok(entries) => Some(entries),
            Err(e) => {
                tracing::warn!("{poller_id}: auth_bruteforce: log payload not parseable: {e}");
                None
            }
        },
        Some(Err(e)) => {
            tracing::warn!("{poller_id}: auth_bruteforce: log fetch failed: {e}");
            None
        }
        None => {
            tracing::warn!("{poller_id}: auth_bruteforce: log fetch returned no result");
            None
        }
    };

    let cursor = get_state(&state.switch_store, cursor_key)
        .await
        .and_then(|s| s.parse::<u64>().ok());

    let (entries, last_id) = match cursor_action(entries.as_deref(), cursor) {
        CursorAction::Hold => return Vec::new(),
        CursorAction::Reset(max_id) => {
            set_state(&state.switch_store, cursor_key, &max_id.to_string()).await;
            return Vec::new();
        }
        // `Advance` is only produced from a batch that parsed, so this cannot
        // observe the `None` above.
        CursorAction::Advance(c) => (entries.unwrap_or_default(), c),
    };
    let max_id = entries.iter().filter_map(|e| parse_log_id(&e.id)).max().unwrap_or(0);

    let fresh: Vec<&LogEntry> = entries
        .iter()
        .filter(|e| parse_log_id(&e.id).is_some_and(|id| id > last_id))
        .collect();
    let parsed: Vec<LoginFailure> = fresh.iter().copied().filter_map(parse_login_failure).collect();

    // Drift's own credential failing is a broken-integration problem, not an
    // intrusion, and its timing signature is indistinguishable from the
    // concurrent-session bypass. Strip it before detection sees it — but only
    // when the source says it really is Drift, never on the username alone.
    let (failures, own) = split_own_credential_failures(
        &parsed,
        &state.config.router.username,
        state.config.router.local_source_ip.as_deref(),
    );
    if !own.is_empty() {
        tracing::warn!(
            count = own.len(),
            user = %state.config.router.username,
            "auth_bruteforce: Drift's own router credential is failing to authenticate — \
             excluded from brute-force detection; check the stored router password",
        );
    }

    // Auth-relevant entries the parser did not recognise. RouterOS wording for
    // login failures varies by service and version; log them so an unhandled
    // shape shows up as a mismatch rather than silence.
    let unparsed: Vec<&str> = fresh
        .iter()
        .filter(|e| {
            let m = e.message.to_ascii_lowercase();
            (m.contains("login") || m.contains("failure") || m.contains("failed"))
                && parse_login_failure(e).is_none()
        })
        .map(|e| e.message.as_str())
        .collect();
    if !unparsed.is_empty() {
        tracing::debug!(
            count = unparsed.len(),
            samples = ?unparsed.iter().take(5).collect::<Vec<_>>(),
            "auth_bruteforce: auth-related log entries not matched by the login-failure parser",
        );
    }
    tracing::debug!(
        new_entries = fresh.len(),
        parsed_failures = failures.len(),
        own_credential_failures = own.len(),
        unparsed_auth_entries = unparsed.len(),
        "auth_bruteforce: log scan complete",
    );

    if max_id > last_id {
        set_state(&state.switch_store, cursor_key, &max_id.to_string()).await;
    }
    if failures.is_empty() {
        return Vec::new();
    }
    detect_bruteforce(&failures)
}

async fn collect_auth_bruteforce_alerts(state: &AppState, rule: &AlertRule, alerts: &mut Vec<PendingAlert>) {
    let channels = parse_channels(&rule.delivery_channels);

    for signal in scan_auth_signals_with_cursor(state, AUTH_BF_POLLER_ID, AUTH_BF_CURSOR_KEY).await {
        let title = if signal.distributed {
            "Distributed Login Brute-Force Detected".to_string()
        } else {
            format!(
                "Login Brute-Force Detected ({} via {})",
                signal.src_ip.as_deref().unwrap_or("local"),
                signal.service
            )
        };
        alerts.push(PendingAlert {
            rule_id: rule.id,
            event_type: "auth_bruteforce".into(),
            severity: signal.severity.into(),
            subject: signal.subject.clone(),
            device_mac: None,
            device_hostname: None,
            device_ip: signal.src_ip.clone(),
            vlan_id: None,
            title,
            body: bruteforce_alert_body(&signal),
            anomaly_id: None,
            delivery_channels: channels.clone(),
            investigation_verdict: None,
            investigation_summary: None,
        });
    }
}

fn parse_channels(json: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(json).unwrap_or_default()
}

// ── Background task ─────────────────────────────────────────────

pub fn spawn_alert_engine(supervisor: &TaskSupervisor, state: AppState, interval_secs: u64) {
    supervisor.spawn("alert_engine", move || {
        let state = state.clone();
        Box::pin(async move {
        // 30 second startup delay
        tokio::time::sleep(Duration::from_secs(30)).await;
        tracing::info!(interval_secs, "alert engine starting");

        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;

            // Resolve all channel secrets from encrypted storage
            let secrets = if let Some(ref sm) = state.secrets_manager {
                let sm_guard = sm.read().await;

                let smtp_password = match sm_guard.decrypt_secret("smtp_password").await {
                    Ok(Some(secret)) => {
                        use secrecy::ExposeSecret;
                        Some(secret.expose_secret().to_string())
                    }
                    _ => None,
                };
                let ntfy_token = match sm_guard.decrypt_secret("alert_channel_ntfy_token").await {
                    Ok(Some(secret)) => {
                        use secrecy::ExposeSecret;
                        Some(secret.expose_secret().to_string())
                    }
                    _ => None,
                };
                let webhook_secret = match sm_guard.decrypt_secret("alert_channel_webhook_secret").await {
                    Ok(Some(secret)) => {
                        use secrecy::ExposeSecret;
                        Some(secret.expose_secret().to_string())
                    }
                    _ => None,
                };
                ChannelSecrets { smtp_password, ntfy_token, webhook_secret }
            } else {
                ChannelSecrets { smtp_password: None, ntfy_token: None, webhook_secret: None }
            };

            evaluate_cycle(
                &state,
                &state.http_client,
                &secrets,
            )
            .await;
        }
    })});
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log(id: &str, time: &str, message: &str) -> LogEntry {
        LogEntry {
            id: id.into(),
            time: time.into(),
            topics: Some("system,error,critical".into()),
            message: message.into(),
        }
    }

    fn failure(user: &str, ip: Option<&str>, service: &str, time: &str) -> LoginFailure {
        failure_p(user, ip, service, time, "")
    }

    fn failure_p(user: &str, ip: Option<&str>, service: &str, time: &str, prefix: &str) -> LoginFailure {
        LoginFailure {
            user: user.into(),
            src_ip: ip.map(Into::into),
            service: service.into(),
            time: time.into(),
            prefix: prefix.into(),
        }
    }

    #[test]
    fn parses_log_ids() {
        assert_eq!(parse_log_id("*1F4"), Some(500));
        assert_eq!(parse_log_id("*a"), Some(10));
        assert_eq!(parse_log_id("1F4"), None);
        assert_eq!(parse_log_id("*zz"), None);
    }

    #[test]
    fn parses_login_failure_with_source() {
        let entry = log("*1", "12:00:00", "login failure for user admin from 10.20.30.99 via api");
        let f = parse_login_failure(&entry).unwrap();
        assert_eq!(f.user, "admin");
        assert_eq!(f.src_ip.as_deref(), Some("10.20.30.99"));
        assert_eq!(f.service, "api");
    }

    /// Real kuat-dev capture: RouterOS logging actions prepend severity prefixes.
    #[test]
    fn parses_prefixed_login_failure() {
        let entry = log(
            "*4",
            "12:00:00",
            "SYS-ERR: login failure for user drift-cve-test from 10.20.25.17 via rest-api",
        );
        let f = parse_login_failure(&entry).unwrap();
        assert_eq!(f.user, "drift-cve-test");
        assert_eq!(f.src_ip.as_deref(), Some("10.20.25.17"));
        assert_eq!(f.service, "rest-api");
        assert_eq!(f.prefix, "SYS-ERR:");
    }

    /// Three logging actions log every failure once each. The reported count
    /// must be the real attempt count, not 3x it.
    #[test]
    fn triple_logged_failures_are_not_multiplied() {
        let mut failures = Vec::new();
        for i in 0..8 {
            let t = format!("12:00:{i:02}");
            for prefix in ["", "SYS-ERR:", "CRITICAL:"] {
                failures.push(failure_p("admin", Some("10.20.25.17"), "rest-api", &t, prefix));
            }
        }
        assert_eq!(failures.len(), 24);
        let signals = detect_bruteforce(&failures);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].count, 8, "count must not be inflated by logging actions");
        assert!(!signals[0].delay_bypass, "distinct seconds must not read as a burst");
    }

    /// Deduplication must not erase genuine same-second concurrent attempts —
    /// that burst is the CVE-2026-16347 delay-bypass signature.
    #[test]
    fn triple_logging_preserves_same_second_burst() {
        let mut failures = Vec::new();
        // 3 concurrent attempts in one second, then 3 spread out — all triple-logged.
        for _ in 0..3 {
            for prefix in ["", "SYS-ERR:", "CRITICAL:"] {
                failures.push(failure_p("admin", Some("10.0.0.9"), "api", "12:00:00", prefix));
            }
        }
        for i in 1..=3 {
            for prefix in ["", "SYS-ERR:", "CRITICAL:"] {
                failures.push(failure_p("admin", Some("10.0.0.9"), "api", &format!("12:00:0{i}"), prefix));
            }
        }
        let signals = detect_bruteforce(&failures);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].count, 6);
        assert!(signals[0].delay_bypass);
        assert_eq!(signals[0].severity, "critical");
    }

    /// Routers where every logging action sets a prefix must still be detected.
    #[test]
    fn detects_when_all_actions_are_prefixed() {
        let failures: Vec<_> = (0..6)
            .map(|i| failure_p("admin", Some("10.0.0.7"), "api", &format!("12:00:0{i}"), "SYS-ERR:"))
            .collect();
        let signals = detect_bruteforce(&failures);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].count, 6);
    }

    #[test]
    fn parses_console_login_failure_without_source() {
        let entry = log("*2", "12:00:00", "login failure for user root via console");
        let f = parse_login_failure(&entry).unwrap();
        assert_eq!(f.user, "root");
        assert_eq!(f.src_ip, None);
        assert_eq!(f.service, "console");
    }

    #[test]
    fn ignores_unrelated_log_entries() {
        let entry = log("*3", "12:00:00", "user admin logged in from 10.0.0.1 via winbox");
        assert!(parse_login_failure(&entry).is_none());
    }

    #[test]
    fn below_threshold_is_silent() {
        let failures: Vec<_> = (0..4)
            .map(|i| failure("admin", Some("10.0.0.5"), "api", &format!("12:00:0{i}")))
            .collect();
        assert!(detect_bruteforce(&failures).is_empty());
    }

    #[test]
    fn burst_from_one_source_warns() {
        let failures: Vec<_> = (0..6)
            .map(|i| failure("admin", Some("10.0.0.5"), "ssh", &format!("12:00:0{i}")))
            .collect();
        let signals = detect_bruteforce(&failures);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].severity, "warning");
        assert_eq!(signals[0].subject, "auth:10.0.0.5:ssh");
        assert!(!signals[0].delay_bypass);
    }

    #[test]
    fn heavy_burst_is_critical() {
        let failures: Vec<_> = (0..16)
            .map(|i| failure("admin", Some("10.0.0.5"), "api", &format!("12:{:02}:00", i)))
            .collect();
        let signals = detect_bruteforce(&failures);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].severity, "critical");
    }

    #[test]
    fn same_second_burst_flags_delay_bypass_and_escalates() {
        // 5 failures, 3 sharing one timestamp — concurrent sessions (CVE-2026-16347).
        let mut failures: Vec<_> = (0..3)
            .map(|_| failure("admin", Some("10.0.0.5"), "api", "12:00:00"))
            .collect();
        failures.push(failure("admin", Some("10.0.0.5"), "api", "12:00:01"));
        failures.push(failure("admin", Some("10.0.0.5"), "api", "12:00:02"));
        let signals = detect_bruteforce(&failures);
        assert_eq!(signals.len(), 1);
        assert!(signals[0].delay_bypass);
        assert_eq!(signals[0].severity, "critical");
        assert!(bruteforce_alert_body(&signals[0]).contains("CVE-2026-16347"));
    }

    #[test]
    fn distributed_sweep_detected_when_sources_stay_under_threshold() {
        // 5 IPs x 3 attempts each = 15 total, all under the per-source threshold.
        let mut failures = Vec::new();
        for ip_octet in 1..=5 {
            for i in 0..3 {
                failures.push(failure(
                    "admin",
                    Some(&format!("10.0.0.{ip_octet}")),
                    "api",
                    &format!("12:0{ip_octet}:0{i}"),
                ));
            }
        }
        let signals = detect_bruteforce(&failures);
        assert_eq!(signals.len(), 1);
        assert!(signals[0].distributed);
        assert_eq!(signals[0].severity, "critical");
        assert_eq!(signals[0].subject, "auth:distributed");
    }

    #[test]
    fn per_source_signal_suppresses_distributed_signal() {
        // One loud source plus background noise → per-source alert only.
        let mut failures: Vec<_> = (0..6)
            .map(|i| failure("admin", Some("10.0.0.5"), "api", &format!("12:00:1{i}")))
            .collect();
        for ip_octet in 1..=4 {
            for i in 0..3 {
                failures.push(failure(
                    "admin",
                    Some(&format!("10.0.1.{ip_octet}")),
                    "api",
                    &format!("12:0{ip_octet}:2{i}"),
                ));
            }
        }
        let signals = detect_bruteforce(&failures);
        assert_eq!(signals.len(), 1);
        assert!(!signals[0].distributed);
    }

    /// Regression: Drift authenticating with a stale stored password produces a
    /// same-second failure burst against its own router. Without the filter it
    /// reads as the concurrent-session bypass and Drift reports itself as an
    /// active intrusion.
    #[test]
    fn drift_own_credential_failures_are_excluded() {
        let failures: Vec<_> = (0..5)
            .map(|_| failure("drift-svc", Some("10.20.25.27"), "rest-api", "12:00:00"))
            .collect();
        // Own source is configured, so these really are Drift's own retries.
        let (kept, own) =
            split_own_credential_failures(&failures, "drift-svc", Some("10.20.25.27"));
        assert_eq!(own.len(), 5, "own-credential failures must be split off");
        assert!(kept.is_empty(), "nothing may survive into detection");
        assert!(
            detect_bruteforce(&kept).is_empty(),
            "Drift's own credential must never raise a brute-force signal"
        );

        // Usernames compare exactly: RouterOS treats `Drift-SVC` as a different
        // account from `drift-svc`, so one must not be able to hide behind the
        // other's exemption.
        let mixed_case: Vec<_> = (0..5)
            .map(|_| failure("Drift-SVC", Some("10.20.25.27"), "rest-api", "12:00:00"))
            .collect();
        let (kept, own) =
            split_own_credential_failures(&mixed_case, "drift-svc", Some("10.20.25.27"));
        assert!(own.is_empty(), "a different account is not Drift's own");
        assert_eq!(kept.len(), 5);
    }

    /// The username-only strip this replaced was a detection killer, not a
    /// false-positive fix: `router.username` defaults to `admin`, so an
    /// attacker guessing that account from anywhere emptied the failure set
    /// and no alert, observation or finding was ever produced.
    #[test]
    fn same_username_from_foreign_ip_still_detected() {
        let failures: Vec<_> = (0..5)
            .map(|_| failure("admin", Some("10.20.35.99"), "api", "12:00:00"))
            .collect();

        // Drift's own address is known and this is not it.
        let (kept, own) = split_own_credential_failures(&failures, "admin", Some("10.20.25.27"));
        assert!(own.is_empty(), "a foreign source is never Drift's own credential");
        assert_eq!(kept.len(), 5);
        let signals = detect_bruteforce(&kept);
        assert_eq!(signals.len(), 1, "a signal must still be produced");
        assert!(
            signals[0].delay_bypass,
            "five failures sharing one timestamp is the same-second burst"
        );

        // And with no address configured at all, the fallback must not blind
        // detection either — that is the whole point of the fallback.
        let (kept, own) = split_own_credential_failures(&failures, "admin", None);
        assert!(own.is_empty());
        assert_eq!(detect_bruteforce(&kept).len(), 1);
    }

    /// Unset `local_source_ip` falls back to the only sources an off-box
    /// attacker cannot put in this field — but only if the field is judged as
    /// an address rather than as text. `src_ip` is cut from a line containing an
    /// attacker-chosen username, so every hostile shape below has to be refused.
    #[test]
    fn own_source_fallback_accepts_only_console_and_loopback() {
        assert!(is_own_source(None, None), "console entries carry no source");
        assert!(is_own_source(Some("127.0.0.1"), None));
        assert!(is_own_source(Some("::1"), None));
        assert!(is_own_source(Some("127.1.2.3"), None), "all of 127/8 is loopback");
        assert!(!is_own_source(Some("10.20.25.27"), None));

        // Hostile: everything a `starts_with("127.")` test used to wave through.
        // The first is what a username of `admin from 127.0.0.1` produced before
        // the parser was hardened, and it is the shape that blinded detection.
        assert!(!is_own_source(Some("127.0.0.1 from 10.20.35.99"), None));
        assert!(!is_own_source(Some(" 127.0.0.1"), None));
        assert!(!is_own_source(Some("127.0.0.1x"), None));
        assert!(!is_own_source(Some("not-an-ip"), None));
        assert!(!is_own_source(Some(""), None));
        assert!(!is_own_source(Some("127.0.0.300"), None));

        // Configured: that address exactly. Not a console entry — Drift always
        // reaches the router over the network.
        assert!(is_own_source(Some("10.20.25.27"), Some("10.20.25.27")));
        assert!(!is_own_source(Some("10.20.25.28"), Some("10.20.25.27")));
        assert!(!is_own_source(None, Some("10.20.25.27")));

        // The same hostile shapes with an address configured: a value that only
        // *contains* the configured address is not the configured address, and
        // a configured value that is not an address matches nothing.
        assert!(!is_own_source(
            Some("10.20.25.27 from 10.20.35.99"),
            Some("10.20.25.27")
        ));
        assert!(!is_own_source(Some("10.20.25.27x"), Some("10.20.25.27")));
        assert!(!is_own_source(Some("10.20.25.27"), Some("drift.kaziik.xyz")));
    }

    /// The full path a crafted attempt takes: raw log line → `parse_login_failure`
    /// → `split_own_credential_failures` → `detect_bruteforce`.
    ///
    /// RouterOS writes the attacker's username verbatim into the middle of the
    /// line, so an attempt as `admin from 127.0.0.1` logs as
    /// `login failure for user admin from 127.0.0.1 from 10.20.35.99 via api`.
    /// Splitting on the *first* ` from ` gave `src_ip` the injected loopback,
    /// which the own-source fallback accepted, so with `router.username` at its
    /// default of `admin` and `local_source_ip` shipped commented out — the
    /// stock configuration — every failure was moved out of detection and no
    /// alert, observation or finding was ever produced.
    #[test]
    fn injected_loopback_in_username_does_not_strip_the_attempt() {
        let entries: Vec<LogEntry> = (0..6)
            .map(|i| {
                log(
                    &format!("*{}", i + 1),
                    &format!("12:00:0{i}"),
                    "login failure for user admin from 127.0.0.1 from 10.20.35.99 via api",
                )
            })
            .collect();

        let parsed: Vec<LoginFailure> = entries.iter().filter_map(parse_login_failure).collect();
        assert_eq!(parsed.len(), 6, "every crafted line must still parse");
        assert_eq!(
            parsed[0].src_ip.as_deref(),
            Some("10.20.35.99"),
            "the source is the one the router appended, not the one in the username"
        );
        assert_eq!(
            parsed[0].user, "admin from 127.0.0.1",
            "the injected text stays in the username where it was typed"
        );
        assert_eq!(parsed[0].service, "api");

        // Stock config: local_source_ip unset, router.username = "admin".
        let (kept, own) = split_own_credential_failures(&parsed, "admin", None);
        assert!(
            own.is_empty(),
            "an injected loopback must never pass as Drift's own credential"
        );
        assert_eq!(kept.len(), 6, "the attempts must survive into detection");

        let signals = detect_bruteforce(&kept);
        assert_eq!(signals.len(), 1, "the attack must still raise a signal");
        assert_eq!(signals[0].src_ip.as_deref(), Some("10.20.35.99"));
        assert_eq!(signals[0].subject, "auth:10.20.35.99:api");
        assert_eq!(signals[0].count, 6);

        // And with loopback configured as Drift's own source, which is the most
        // generous reading of the crafted line available to the attacker.
        let (kept, own) = split_own_credential_failures(&parsed, "admin", Some("127.0.0.1"));
        assert!(own.is_empty());
        assert_eq!(detect_bruteforce(&kept).len(), 1);
    }

    /// The username cannot move either boundary, because both are matched from
    /// the right and the router writes both at the end of the line.
    #[test]
    fn username_cannot_move_the_source_or_service_boundary() {
        // ` via ` in the username: the service is still the real trailing one.
        let f = parse_login_failure(&log(
            "*1",
            "12:00:00",
            "login failure for user admin via api from 10.20.35.99 via ssh",
        ))
        .unwrap();
        assert_eq!(f.user, "admin via api");
        assert_eq!(f.src_ip.as_deref(), Some("10.20.35.99"));
        assert_eq!(f.service, "ssh");

        // Both injected at once.
        let f = parse_login_failure(&log(
            "*2",
            "12:00:00",
            "login failure for user x from ::1 via console from 10.20.35.99 via api",
        ))
        .unwrap();
        assert_eq!(f.user, "x from ::1 via console");
        assert_eq!(f.src_ip.as_deref(), Some("10.20.35.99"));
        assert_eq!(f.service, "api");
        assert!(
            !is_own_source(f.src_ip.as_deref(), None),
            "the real source is remote"
        );

        // A prefix still comes off, and a console entry still parses as one.
        let f = parse_login_failure(&log(
            "*3",
            "12:00:00",
            "SYS-ERR: login failure for user root via console",
        ))
        .unwrap();
        assert_eq!(f.prefix, "SYS-ERR:");
        assert_eq!(f.user, "root");
        assert_eq!(f.src_ip, None);
        assert_eq!(f.service, "console");
    }

    /// A payload that does not deserialize says nothing about the log's
    /// position. Treating it as an empty buffer rewinds the cursor to 0 and
    /// replays the entire ring buffer on the next cycle.
    #[test]
    fn unparseable_log_payload_holds_the_cursor() {
        assert_eq!(cursor_action(None, Some(500)), CursorAction::Hold);
        assert_eq!(cursor_action(None, None), CursorAction::Hold);

        // A batch that parsed and is genuinely empty is a real buffer reset.
        assert_eq!(cursor_action(Some(&[]), Some(500)), CursorAction::Reset(0));

        let entries = [log("*1F4", "12:00:00", "login failure for user admin via api")];
        assert_eq!(cursor_action(Some(&entries), None), CursorAction::Reset(500));
        assert_eq!(cursor_action(Some(&entries), Some(400)), CursorAction::Advance(400));
        // Cursor ahead of the buffer = the router rebooted.
        assert_eq!(cursor_action(Some(&entries), Some(600)), CursorAction::Reset(500));
    }

    /// The distributed branch joins its services for display. Correlation needs
    /// the parsed list, or the always-critical multi-source case is dropped.
    #[test]
    fn distributed_signal_carries_service_list() {
        let mut failures = Vec::new();
        for ip_octet in 1..=5 {
            for (i, service) in ["api", "ssh", "winbox"].iter().enumerate() {
                failures.push(failure(
                    "admin",
                    Some(&format!("10.0.0.{ip_octet}")),
                    service,
                    &format!("12:0{ip_octet}:0{i}"),
                ));
            }
        }
        let signals = detect_bruteforce(&failures);
        assert_eq!(signals.len(), 1);
        assert!(signals[0].distributed);
        assert!(signals[0].services.len() > 1, "joined display string is not parseable");
        assert_eq!(
            signals[0].services,
            vec![
                ("api".to_string(), 5),
                ("ssh".to_string(), 5),
                ("winbox".to_string(), 5),
            ],
            "each service carries its own failure count, not the sweep total"
        );
        assert_eq!(signals[0].count, 15, "the sweep total stays on the signal");
        assert_eq!(signals[0].service, "api, ssh, winbox", "display string unchanged");
        assert_eq!(signals[0].sources.len(), 5);
        assert_eq!(signals[0].signal_id(), "auth.login_failure_distributed");
    }

    /// The counts a distributed sweep hands to correlation must be per service.
    /// 20 ssh failures spread over six sources plus one stray api failure is an
    /// ssh sweep; attributing the 21-event total to the api surface as well is
    /// what turned it into a confirmed api exploitation finding.
    #[test]
    fn distributed_signal_counts_each_service_separately() {
        let mut failures = Vec::new();
        for src in 1..=6 {
            for i in 0..3 {
                failures.push(failure(
                    "admin",
                    Some(&format!("10.0.0.{src}")),
                    "ssh",
                    &format!("12:0{src}:0{i}"),
                ));
            }
        }
        // 18 ssh so far; two more keep every source under the per-source
        // threshold of 5 while clearing the distributed total of 15.
        failures.push(failure("admin", Some("10.0.0.1"), "ssh", "12:10:00"));
        failures.push(failure("admin", Some("10.0.0.2"), "ssh", "12:10:01"));
        failures.push(failure("admin", Some("10.0.0.3"), "api", "12:10:02"));

        let signals = detect_bruteforce(&failures);
        assert_eq!(signals.len(), 1, "no source reaches the per-source threshold");
        assert!(signals[0].distributed);
        assert_eq!(signals[0].count, 21, "the sweep total spans both services");
        assert_eq!(
            signals[0].services,
            vec![("api".to_string(), 1), ("ssh".to_string(), 20)],
            "the api service saw exactly one failure and must say so"
        );
    }

    #[test]
    fn same_second_burst_maps_to_strong_signal() {
        let mut failures: Vec<_> = (0..3)
            .map(|_| failure("admin", Some("10.0.0.5"), "api", "12:00:00"))
            .collect();
        failures.push(failure("admin", Some("10.0.0.5"), "api", "12:00:01"));
        failures.push(failure("admin", Some("10.0.0.5"), "api", "12:00:02"));
        let signals = detect_bruteforce(&failures);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].signal_id(), "auth.login_failure_same_second_burst");
        assert_eq!(
            signals[0].services,
            vec![("api".to_string(), 5)],
            "a per-source signal carries its one service and that service's count"
        );

        // A plain burst that never shares a second stays the weaker id.
        let spread: Vec<_> = (0..6)
            .map(|i| failure("admin", Some("10.0.0.5"), "api", &format!("12:00:0{i}")))
            .collect();
        assert_eq!(
            detect_bruteforce(&spread)[0].signal_id(),
            "auth.login_failure_burst"
        );
    }

    /// Every id `signal_id()` can return must be one core declares it emits,
    /// or the catalog can never link an advisory to it.
    #[test]
    fn emitted_signal_ids_are_registered() {
        let mut failures: Vec<_> = (0..3)
            .map(|_| failure("admin", Some("10.0.0.5"), "api", "12:00:00"))
            .collect();
        failures.push(failure("admin", Some("10.0.0.5"), "api", "12:00:01"));
        failures.push(failure("admin", Some("10.0.0.5"), "api", "12:00:02"));
        let mut spread: Vec<_> = (0..6)
            .map(|i| failure("admin", Some("10.0.0.5"), "ssh", &format!("12:00:0{i}")))
            .collect();
        for ip_octet in 1..=5 {
            for i in 0..3 {
                spread.push(failure(
                    "admin",
                    Some(&format!("10.9.0.{ip_octet}")),
                    "api",
                    &format!("13:0{ip_octet}:0{i}"),
                ));
            }
        }
        let distributed: Vec<_> = (1..=5)
            .flat_map(|ip_octet| {
                (0..3).map(move |i| {
                    failure(
                        "admin",
                        Some(&format!("10.0.0.{ip_octet}")),
                        "api",
                        &format!("12:0{ip_octet}:0{i}"),
                    )
                })
            })
            .collect();

        for set in [&failures, &spread, &distributed] {
            for signal in detect_bruteforce(set) {
                assert!(
                    crate::advisory::signals::is_known_signal(signal.signal_id()),
                    "{} is not in EMITTED_SIGNALS",
                    signal.signal_id()
                );
            }
        }
    }
}
