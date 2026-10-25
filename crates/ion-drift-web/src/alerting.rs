//! Alerting engine — evaluates alert rules, enforces cooldowns, delivers notifications.
//!
//! Phase 1–4: anomaly_critical, anomaly_correlated, device_new, device_flagged, port_violation,
//! anomaly_warning, interface_down, device_offline, dhcp_pool_exhausted, firewall_drop_spike,
//! auth_bruteforce.
//! Delivery: ntfy, webhook, smtp.

use std::collections::{BTreeMap, BTreeSet};
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

/// Whether the cooldown will stop this subject firing right now.
///
/// A named inverse of [`is_cooled_down`], whose name reads as the opposite of
/// what it returns — it is `true` when the cooldown has *elapsed* and the alert
/// is free to fire. Both the delivery gate and the planner that has to
/// anticipate it go through this one predicate, so they cannot disagree about
/// the direction: a flip here flips both together instead of splitting them.
/// Split, they would deliver exactly the cooled alerts and suppress exactly the
/// deliverable ones, with every unit test still green.
async fn cooldown_suppresses(store: &SwitchStore, rule_id: i64, subject: &str, cooldown_secs: i64) -> bool {
    !is_cooled_down(store, rule_id, subject, cooldown_secs).await
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
        if let Some(anomaly_id) = alert.anomaly_id
            && let Ok(Some(inv)) = behavior_store.get_investigation_by_anomaly(anomaly_id).await {
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

    // Apply verdict_filter: drop alerts whose investigation verdict doesn't match the rule filter
    pending_alerts.retain(|alert| {
        if let Some(rule) = enabled_rules.iter().find(|r| r.id == alert.rule_id)
            && let Some(ref filter) = rule.verdict_filter {
                // verdict_filter is a comma-separated list of accepted verdicts
                let accepted: Vec<&str> = filter.split(',').map(|s| s.trim()).collect();
                if let Some(ref verdict) = alert.investigation_verdict {
                    return accepted.iter().any(|a| a.eq_ignore_ascii_case(verdict));
                }
                // No verdict yet — keep the alert (investigation may not have run)
            }
        true
    });

    // Deliver alerts
    let mut total_fired = 0;
    for alert in &pending_alerts {
        // Check cooldown. Same predicate the auth planner uses upstream, so the
        // two cannot disagree about which alerts this loop will skip.
        if cooldown_suppresses(switch_store, alert.rule_id, &alert.subject,
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
    /// (mac, best_ip, hostname, manufacturer, vlan_id)
    type NewDeviceRow = (String, Option<String>, Option<String>, Option<String>, Option<i64>);
    let rows: Vec<NewDeviceRow> = {
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
    /// (mac, best_ip, hostname, vlan_id)
    type FlaggedDeviceRow = (String, Option<String>, Option<String>, Option<i64>);
    let flagged: Vec<FlaggedDeviceRow> = {
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
    /// (mac, best_ip, hostname, vlan_id, last_seen)
    type ConfirmedDeviceRow = (String, Option<String>, Option<String>, Option<i64>, i64);
    let devices: Vec<ConfirmedDeviceRow> = {
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
            if let Some((start_s, end_s)) = range_str.split_once('-')
                && let (Ok(start), Ok(end)) = (
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
/// accepted `"127.0.0.1 from 203.0.113.99"` — exactly what a username of
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
/// Per-service deduped failure totals for one scan cycle, thresholds NOT
/// applied. `BruteforceSignal` exists only above the alert thresholds, and the
/// per-source and distributed signals deliberately overlap — so neither one is
/// a usable count. The advisory accumulator's cross-cycle counter needs the
/// below-threshold failures too, or a low-and-slow run that never crosses a
/// per-cycle threshold stays invisible forever.
#[derive(Debug, PartialEq)]
pub(crate) struct ServiceFailureTotal {
    pub service: String,
    /// Deduped count — same `dedup_logging_actions` pass the detector runs, so
    /// this view and the signal view of one cycle can never disagree about
    /// what a single failure is.
    pub count: usize,
    /// Distinct source IPs, sorted. Console failures count but contribute none.
    pub sources: Vec<String>,
}

/// Everything one pass over the fresh log entries yields: the thresholded
/// brute-force signals and the pre-threshold per-service totals. One struct so
/// a consumer cannot accidentally run the parse twice against one cursor.
pub(crate) struct AuthScan {
    pub signals: Vec<BruteforceSignal>,
    pub service_totals: Vec<ServiceFailureTotal>,
}

impl AuthScan {
    fn empty() -> Self {
        Self {
            signals: Vec::new(),
            service_totals: Vec::new(),
        }
    }
}

fn service_failure_totals(failures: &[LoginFailure]) -> Vec<ServiceFailureTotal> {
    // Identical grouping to detect_bruteforce: (source, service), then the
    // logging-action dedup per group.
    let mut groups: BTreeMap<(String, String), Vec<&LoginFailure>> = BTreeMap::new();
    for f in failures {
        let src = f.src_ip.clone().unwrap_or_else(|| "local".into());
        groups.entry((src, f.service.clone())).or_default().push(f);
    }
    let mut totals: BTreeMap<String, ServiceFailureTotal> = BTreeMap::new();
    for ((src, service), group) in &groups {
        let deduped = dedup_logging_actions(group);
        if deduped.is_empty() {
            continue;
        }
        let entry = totals
            .entry(service.clone())
            .or_insert_with(|| ServiceFailureTotal {
                service: service.clone(),
                count: 0,
                sources: Vec::new(),
            });
        entry.count += deduped.len();
        if src != "local" {
            entry.sources.push(src.clone());
        }
    }
    totals
        .into_values()
        .map(|mut t| {
            t.sources.sort();
            t.sources.dedup();
            t
        })
        .collect()
}

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

    // Low-and-slow sweep: many sources, each of them individually quiet, adding
    // up to a coordinated guessing run.
    //
    // Independent of the per-source branch above **by design**: it runs whether
    // or not any single source crossed the per-source threshold. It used to be
    // gated on `signals.is_empty()`, and that gate was an off switch an attacker
    // could buy for one burner address — 90 failures spread over 30 sources
    // raised the sweep, and 5 more failures from one throwaway IP made those 90
    // vanish, leaving only a `warning` about the decoy. Input an attacker
    // chooses must never be able to silence a detector, so the two detectors
    // answer two different questions and neither one gates the other.
    //
    // The decoy's own failures deliberately stay *inside* `total_failures` and
    // `sources`. Excluding a source because it already raised its own signal
    // would just be a second off switch: every address the attacker pushes over
    // the per-source threshold would be subtracted from the sweep they are
    // running.
    //
    // Both signals landing in one cycle is a volume problem, and volume is
    // handled at delivery in `select_auth_alerts` — never here, where anything
    // that suppresses costs detection.
    if total_failures >= AUTH_BF_DISTRIBUTED_TOTAL {
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

/// Join up to `max` entries and summarise the remainder as `(+N more)`.
///
/// The only way a list of attacker-supplied addresses reaches a notification
/// body. See [`ALERT_BODY_SOURCE_LIST_MAX`] for why the bound is not optional.
fn bounded_source_list(items: &[String], max: usize) -> String {
    let shown: Vec<&str> = items.iter().take(max).map(String::as_str).collect();
    let extra = items.len() - shown.len();
    if extra > 0 {
        format!("{} (+{extra} more)", shown.join(", "))
    } else {
        shown.join(", ")
    }
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
        // The sources are named here, not left to the roll-up sentence. A
        // signal folded into this sweep produces no alert of its own, so a body
        // that says only "multiple source IPs" leaves that appended sentence as
        // the single place a folded address is ever named — and an operator
        // reading a truncated push then cannot tell which hosts were involved.
        // Bounded, because the number of addresses is the attacker's choice.
        format!(
            "{} failed login attempts via {} from {} source IPs ({}) since the last check (users tried: {users_label}). Pattern is consistent with a distributed credential-guessing sweep.",
            signal.count,
            signal.service,
            signal.sources.len(),
            bounded_source_list(&signal.sources, ALERT_BODY_SOURCE_LIST_MAX),
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

// ── Auth alert delivery budget ──────────────────────────────────
//
// The detector emits everything it sees; deciding how much of that becomes a
// notification is a delivery concern and lives here. Keeping the two apart is
// the whole point: a cap in the detector is a blind spot, a cap here is only a
// quieter inbox.

/// Auth alerts one cycle may deliver before the rest are rolled into a single
/// summary. Detection is uncapped — this bounds notifications only.
///
/// A module constant for now; `[auth_detection]` config lands in a later phase.
const AUTH_ALERT_BUDGET: usize = 10;

/// Source addresses one alert body may name before the remainder is summarised
/// as a count.
///
/// Every source list that reaches a notification goes through
/// [`bounded_source_list`] and stops here. The count of addresses in a cycle is
/// chosen by whoever is knocking on the router, so an unbounded join hands an
/// attacker the size of the push payload.
const ALERT_BODY_SOURCE_LIST_MAX: usize = 10;

/// Cooldown subject for the budget summary alert.
///
/// Constant on purpose. The cooldown is keyed `(rule_id, subject)`, so a subject
/// carrying a count, a source or a timestamp would mint a fresh key every cycle,
/// the cooldown would never match, and the alert storm the budget exists to stop
/// would be rebuilt through the back door. Anything variable belongs in the
/// body.
const AUTH_BUDGET_SUBJECT: &str = "auth:budget";

/// Tracing target for the withheld-signal record, named in the summary body.
///
/// One constant on both sides on purpose. The summary tells the operator where
/// the withheld signals are, and the only thing that makes that true is the
/// event actually carrying this target — `tracing` defaults a target to
/// `module_path!()`, so a message that merely *starts* with the word is not
/// filterable by it and the instruction fails against `RUST_LOG` or any
/// structured-log target filter. Interpolating the same constant into the body
/// and passing it as `target:` means the two cannot drift: change it here and
/// the sentence changes with it.
const AUTH_WITHHELD_LOG_TARGET: &str = "auth_bruteforce";

/// Delivery precedence for a severity label — lower sorts first.
///
/// Unknown labels sort last rather than panicking: an unrecognised severity is
/// a reason to deliver something later, never a reason to drop a cycle.
fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "warning" => 1,
        _ => 2,
    }
}

/// Whether a broader signal's body can stand in for this one.
///
/// Only the routine per-source bursts qualify. A critical one carries something
/// a sweep's body does not — a heavy count, or the same-second concurrency that
/// is the CVE-2026-16347 delay-bypass signature — so folding it into a generic
/// sweep body would lose that at delivery. `delay_bypass` is checked in its own
/// right and not left to the severity label, so a later change to how severity
/// is computed cannot quietly make the bypass signature roll-uppable.
fn is_rollup_candidate(signal: &BruteforceSignal) -> bool {
    !signal.distributed && !signal.delay_bypass && severity_rank(signal.severity) > 0
}

/// The delivery decision for one cycle's signals.
///
/// The four fields are a partition of `0..signals.len()`: every input signal
/// lands in exactly one of `deliver`, `rolled_up`, `cooled`, or the
/// `over_budget` count, and
/// `deliver.len() + rolled_up.len() + cooled.len() + over_budget == signals.len()`
/// always. That identity is the only thing standing between a delivery budget
/// and a silent drop, so it is maintained by construction in
/// [`select_auth_alerts`] rather than assumed.
pub(crate) struct AuthAlertPlan {
    /// Indices into the input slice — the caller keeps ownership.
    pub deliver: Vec<usize>,
    /// Indices of the signals folded into a delivered broad signal's body
    /// instead of alerted on separately.
    ///
    /// Signal indices, not source names. One source with N qualifying
    /// `(source, service)` groups produces N separate signals, and a
    /// deduplicated list of source names collapsed all N of them to a single
    /// entry: the accounting then under-counted by N-1, those signals were
    /// delivered nowhere, and because `over_budget` stayed 0 no "withheld"
    /// summary fired to admit it. One source across 25 services became
    /// `deliver=1, rolled_up=1, over_budget=0` for 26 signals — 24 of them
    /// vanished. Indices cannot collapse, so the partition holds by
    /// construction; the readable source list is derived from these indices at
    /// render time by [`AuthAlertPlan::rolled_up_sources`], where deduplicating
    /// is a display choice and costs no accounting.
    pub rolled_up: Vec<usize>,
    /// Signals whose own subject is inside its cooldown window this cycle.
    ///
    /// These are suppressed by the operator's own rate control, which is the
    /// one form of "delivered nowhere" that is intended. They are tracked as
    /// indices rather than discarded so the partition stays checkable and so a
    /// future surface can say *why* a signal was quiet.
    pub cooled: Vec<usize>,
    /// Signals dropped by the budget. Non-empty produces one summary alert.
    ///
    /// Indices, not a bare count, for the reason [`Self::rolled_up`] gives and
    /// for one more: the summary tells the operator these are in the server
    /// log, and only the indices can name them there.
    pub withheld: Vec<usize>,
}

impl AuthAlertPlan {
    /// How many signals the budget dropped this cycle.
    fn over_budget(&self) -> usize {
        self.withheld.len()
    }

    /// The subjects behind [`Self::withheld`], sorted and deduplicated.
    ///
    /// Display only — the accounting stays in indices, so collapsing two
    /// signals that share a subject shortens a log line without losing one.
    fn withheld_subjects<'a>(&self, signals: &'a [BruteforceSignal]) -> BTreeSet<&'a str> {
        self.withheld
            .iter()
            .map(|&i| signals[i].subject.as_str())
            .collect()
    }

    /// The distinct source addresses behind [`Self::rolled_up`], sorted.
    ///
    /// Display only. Deduplication is safe here precisely because the
    /// accounting is kept in indices — collapsing two signals from one source
    /// shortens a sentence, it does not lose a signal.
    fn rolled_up_sources(&self, signals: &[BruteforceSignal]) -> Vec<String> {
        let mut sources: Vec<String> = self
            .rolled_up
            .iter()
            .filter_map(|&i| signals[i].src_ip.clone())
            .collect();
        sources.sort();
        sources.dedup();
        sources
    }
}

/// Choose which of a cycle's signals become notifications.
///
/// Detection is never suppressed — every signal still reaches the advisory
/// observation path regardless of what this returns. This decides delivery
/// only, so the worst case is a quieter inbox, never a blind detector.
///
/// Broadest-first: a distributed sweep describes the whole event, so the
/// per-source signals inside it are rolled into its body rather than delivered
/// beside it.
///
/// Ordering within each tier is severity, then failure count, then subject, so
/// the plan for a given cycle is deterministic and the loudest evidence is the
/// last thing a budget can push out. A signal is only ever rolled up into a
/// sweep this plan actually delivers; if the sweep does not go out, nothing is
/// folded into it.
///
/// `suppressed` carries the subjects the *cooldown* will drop, and it is a
/// parameter rather than a lookup for the same reason `now` is a parameter to a
/// windowed detector: it makes every one of these branches a deterministic unit
/// test instead of a database race.
///
/// **Why the plan has to know.** The cooldown check lives downstream in
/// `evaluate_cycle`, which knows nothing about this plan and simply skips a
/// cooled alert — without recording history and without arming any other
/// subject. So a plan built as though a cooled signal were delivered loses
/// everything it decided on that basis. Two ways, both live before this
/// parameter existed:
///
/// * `auth:distributed` is one constant subject on a 600s cooldown while the
///   engine cycles every 60s, and a sweep's `sources` is *every* address in the
///   batch. Nine cycles in ten the sweep was dropped downstream and every
///   per-source burst folded into it — each with a clear cooldown of its own,
///   each of which would have alerted standalone — was dropped with it. No
///   notification, no history row, no cooldown armed, and the log cursor had
///   already advanced past the evidence.
/// * A cooled signal still consumed one of `max_alerts`, pushing a signal that
///   *would* have been delivered into `over_budget`.
///
/// Removing a cooled signal from the plan first makes both structural: it is
/// not in `deliver`, so it contributes nothing to `covered` and absorbs
/// nothing, and it holds no budget slot.
///
/// Every index in `0..signals.len()` is classified exactly once, into exactly
/// one of the four buckets — see [`AuthAlertPlan`] for what a bucket that can
/// swallow two signals at once costs.
fn select_auth_alerts(
    signals: &[BruteforceSignal],
    max_alerts: usize,
    suppressed: &BTreeSet<String>,
) -> AuthAlertPlan {
    // Cooled signals leave the running before anything else is decided. They
    // are not candidates for delivery, they cannot cover a source, and they do
    // not hold a budget slot.
    let (cooled, live): (Vec<usize>, Vec<usize>) =
        (0..signals.len()).partition(|&i| suppressed.contains(&signals[i].subject));
    let (mut broad, mut narrow): (Vec<usize>, Vec<usize>) =
        live.into_iter().partition(|&i| signals[i].distributed);
    let by_precedence = |idx: &mut Vec<usize>| {
        idx.sort_by(|a, b| {
            let (x, y) = (&signals[*a], &signals[*b]);
            severity_rank(x.severity)
                .cmp(&severity_rank(y.severity))
                .then_with(|| y.count.cmp(&x.count))
                .then_with(|| x.subject.cmp(&y.subject))
        });
    };
    by_precedence(&mut broad);
    by_precedence(&mut narrow);

    // Three buckets, one `push` per index, no branch that skips them all —
    // `withheld` is kept as indices rather than a bare counter for the same
    // reason `rolled_up` is: a count can be forgotten, a moved index cannot.
    let mut deliver: Vec<usize> = Vec::new();
    let mut rolled_up: Vec<usize> = Vec::new();
    let mut withheld: Vec<usize> = Vec::new();

    for i in broad {
        if deliver.len() < max_alerts {
            deliver.push(i);
        } else {
            withheld.push(i);
        }
    }

    // Sources a delivered sweep already accounts for. Built from `deliver`, not
    // from every broad signal, so a sweep that lost its own budget fight — or
    // its cooldown, which is the same silent drop one layer down — cannot
    // absorb signals that then go nowhere.
    let covered: BTreeSet<&str> = deliver
        .iter()
        .flat_map(|&i| signals[i].sources.iter().map(String::as_str))
        .collect();

    for i in narrow {
        let signal = &signals[i];
        // A console signal carries no source, so it is never inside a sweep —
        // the `local` sentinel must not be able to match one.
        let folds_into_a_sweep = signal
            .src_ip
            .as_deref()
            .is_some_and(|src| covered.contains(src) && is_rollup_candidate(signal));
        if folds_into_a_sweep {
            rolled_up.push(i);
        } else if deliver.len() < max_alerts {
            deliver.push(i);
        } else {
            withheld.push(i);
        }
    }

    let plan = AuthAlertPlan { deliver, rolled_up, cooled, withheld };
    debug_assert_eq!(
        plan.deliver.len() + plan.rolled_up.len() + plan.cooled.len() + plan.over_budget(),
        signals.len(),
        "auth alert plan must partition its input: every signal is delivered, \
         folded into a delivered signal, suppressed by its own cooldown, or \
         counted as withheld",
    );
    plan
}

/// The body an operator actually reads for one delivered signal: the signal's
/// own body, plus the roll-up sentence when this is the sweep that stands in
/// for signals folded into it.
///
/// Split out of `collect_auth_bruteforce_alerts` so the composed text is
/// testable without an `AppState` — the roll-up sentence is the only place a
/// folded source is named, which makes it worth a test of its own.
fn delivered_bruteforce_body(
    signal: &BruteforceSignal,
    plan: &AuthAlertPlan,
    signals: &[BruteforceSignal],
    attach_rollup: bool,
) -> String {
    let mut body = bruteforce_alert_body(signal);
    if attach_rollup && !plan.rolled_up.is_empty() {
        // Counted in signals, named in sources: the two differ whenever one
        // address crossed the threshold on more than one service, and quoting
        // a source count taken from a signal list would overstate how many
        // hosts are involved.
        let sources = plan.rolled_up_sources(signals);
        body.push_str(&format!(
            " {} further signal(s), from {} source IP(s) in this sweep, also crossed the per-source threshold on their own and are reported here rather than as separate alerts: {}.",
            plan.rolled_up.len(),
            sources.len(),
            bounded_source_list(&sources, ALERT_BODY_SOURCE_LIST_MAX),
        ));
    }
    body
}

/// Content for the single summary alert emitted when a cycle exceeds the budget.
struct AuthBudgetSummary {
    /// Always [`AUTH_BUDGET_SUBJECT`] — see that constant for why it is fixed.
    subject: String,
    severity: &'static str,
    title: String,
    body: String,
}

fn auth_budget_summary(plan: &AuthAlertPlan, signals: &[BruteforceSignal]) -> AuthBudgetSummary {
    // The highest severity the cycle produced, not the highest that happened to
    // be withheld: a notice standing in for withheld alerts must never be
    // quieter than what it stands in for. Over-stating it costs a louder
    // notification; under-stating it hides a critical behind a budget.
    let severity = if signals.iter().any(|s| severity_rank(s.severity) == 0) {
        "critical"
    } else {
        "warning"
    };
    AuthBudgetSummary {
        subject: AUTH_BUDGET_SUBJECT.to_string(),
        severity,
        title: "Login Brute-Force Alerts Withheld (delivery budget)".to_string(),
        // Names only surfaces that exist and provably hold the data.
        //
        // `record_alert_history` runs once per DELIVERED alert, so the withheld
        // signals are absent from alert history by construction — pointing there
        // would be wrong. An earlier draft pointed at "the Advisories and
        // Findings pages" instead, and both halves were false: there is no
        // advisory route in the web crate at all, and `exploitation::evaluate`
        // only raises a finding for a `strong` signal whose advisory covers the
        // observed surface, while `auth.login_failure_burst` is `corroborating`
        // — so a withheld burst on ssh or winbox reaches neither. Sending an
        // operator somewhere the data provably is not is the same failure this
        // budget exists to avoid, so this says what is true: the withheld
        // signals are in the server log, and the fix is the threshold.
        body: format!(
            "{} further login brute-force alert(s) were withheld this cycle after {} were delivered. \
             This is a delivery budget, not a detection limit — every signal was still detected and \
             counted, and every withheld subject is named in the ion-drift server log under the \
             tracing target `{}`. They are deliberately not written to alert history, which records \
             delivered alerts only. A cycle this loud usually means an attack in progress: treat \
             the delivered alerts as a sample, not the whole picture.",
            plan.over_budget(),
            plan.deliver.len(),
            AUTH_WITHHELD_LOG_TARGET,
        ),
    }
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

/// Read the router log ring buffer forward from `cursor_key` and return both
/// views of the new entries: the thresholded brute-force signals and the
/// pre-threshold per-service failure totals.
///
/// Kept here (rather than in `advisory::exploitation`) because the parsers and
/// thresholds it drives live in this module. Each consumer passes its own
/// cursor key so no consumer can drain entries another one has not seen yet,
/// and its own `poller_id` because `router_queue` keys pending work by that id
/// and evicts the older batch when two submitters collide on it.
pub(crate) async fn scan_auth_with_cursor(
    state: &AppState,
    poller_id: &str,
    cursor_key: &str,
) -> AuthScan {
    // Fetch the router log ring buffer through the shared queue.
    let results = match state
        .router_queue
        .submit(poller_id, Priority::Normal, vec![QueuedRequest::get("log")])
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("{poller_id}: auth_bruteforce: log fetch failed: {e}");
            return AuthScan::empty();
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
        CursorAction::Hold => return AuthScan::empty(),
        CursorAction::Reset(max_id) => {
            set_state(&state.switch_store, cursor_key, &max_id.to_string()).await;
            return AuthScan::empty();
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
        return AuthScan::empty();
    }
    AuthScan {
        signals: detect_bruteforce(&failures),
        service_totals: service_failure_totals(&failures),
    }
}

/// The subjects the cooldown will stop from firing this cycle.
///
/// This is the cooldown that `evaluate_cycle` applies downstream, resolved
/// *before* planning. That loop skips a cooled alert without recording it and
/// without arming anything else, so a plan that folded signals into a cooled
/// carrier — or spent budget on one — would lose them with no trace. Asking
/// here costs one indexed read per *distinct* subject and makes the loss
/// impossible instead of unlikely.
///
/// Split out of [`collect_auth_bruteforce_alerts`] so it can be tested against
/// a real store without an `AppState`. That is not tidiness: this function is
/// where the suppressed set is *built*, and inverting it delivers exactly the
/// cooled alerts while silently suppressing exactly the deliverable ones —
/// a flip every pure-function test below is blind to, because they are handed
/// the finished set as input.
async fn suppressed_auth_subjects(
    store: &SwitchStore,
    rule_id: i64,
    cooldown_secs: i64,
    signals: &[BruteforceSignal],
) -> BTreeSet<String> {
    let mut suppressed: BTreeSet<String> = BTreeSet::new();
    let mut checked: BTreeSet<&str> = BTreeSet::new();
    for signal in signals {
        // One query per distinct subject: several signals can share none today,
        // but the summary subject and any future shared subject would repeat.
        if !checked.insert(signal.subject.as_str()) {
            continue;
        }
        if cooldown_suppresses(store, rule_id, &signal.subject, cooldown_secs).await {
            suppressed.insert(signal.subject.clone());
        }
    }
    suppressed
}

async fn collect_auth_bruteforce_alerts(state: &AppState, rule: &AlertRule, alerts: &mut Vec<PendingAlert>) {
    let channels = parse_channels(&rule.delivery_channels);

    let signals = scan_auth_with_cursor(state, AUTH_BF_POLLER_ID, AUTH_BF_CURSOR_KEY)
        .await
        .signals;

    let suppressed =
        suppressed_auth_subjects(&state.switch_store, rule.id, rule.cooldown_seconds, &signals).await;

    // Detection above, delivery below. Everything the scan produced has already
    // been counted; the plan only decides how much of it is worth notifying on.
    let plan = select_auth_alerts(&signals, AUTH_ALERT_BUDGET, &suppressed);

    let mut rollup_noted = false;
    for &idx in &plan.deliver {
        let signal = &signals[idx];
        let title = if signal.distributed {
            "Distributed Login Brute-Force Detected".to_string()
        } else {
            format!(
                "Login Brute-Force Detected ({} via {})",
                signal.src_ip.as_deref().unwrap_or("local"),
                signal.service
            )
        };
        // Rolled-up sources ride in the body of the broad signal that absorbed
        // them, so nothing that was folded away goes unreported. Attached to the
        // first delivered sweep — `detect_bruteforce` produces at most one today.
        //
        // The `!plan.rolled_up.is_empty()` term matters only if that ever stops
        // being true: without it the flag flips on the first sweep even when it
        // absorbed nothing, and a second sweep would silently lose its roll-up
        // sentence while its folded signals still produce no alerts of their own.
        // `select_auth_alerts` already distributes folding across multiple sweeps
        // correctly, so this keeps the two halves consistent.
        let attach_rollup = signal.distributed && !rollup_noted && !plan.rolled_up.is_empty();
        rollup_noted |= attach_rollup;
        let body = delivered_bruteforce_body(signal, &plan, &signals, attach_rollup);
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
            body,
            anomaly_id: None,
            delivery_channels: channels.clone(),
            investigation_verdict: None,
            investigation_summary: None,
        });
    }

    if plan.over_budget() > 0 {
        let summary = auth_budget_summary(&plan, &signals);
        // The summary body tells the operator the withheld signals are in this
        // log, so they have to actually be here — a count alone would make that
        // sentence another pointer at data that is not where it says. The
        // subjects are bounded by the budget arithmetic, not by attacker
        // volume: everything past `AUTH_ALERT_BUDGET` is named once.
        let withheld_subjects: Vec<&str> = plan.withheld_subjects(&signals).into_iter().collect();
        // `warn`, not `info`, and on its own target. This line is the *only*
        // record of these subjects — the summary body says so, and alert
        // history excludes them by construction — so a deployment that quiets
        // itself to `RUST_LOG=warn` must not be the thing that erases them.
        tracing::warn!(
            target: AUTH_WITHHELD_LOG_TARGET,
            withheld = plan.over_budget(),
            delivered = plan.deliver.len(),
            rolled_up = plan.rolled_up.len(),
            cooled = plan.cooled.len(),
            withheld_subjects = ?withheld_subjects,
            "delivery budget reached — detection is unaffected",
        );
        alerts.push(PendingAlert {
            rule_id: rule.id,
            event_type: "auth_bruteforce".into(),
            severity: summary.severity.into(),
            subject: summary.subject,
            device_mac: None,
            device_hostname: None,
            device_ip: None,
            vlan_id: None,
            title: summary.title,
            body: summary.body,
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
    fn service_totals_count_below_threshold_failures() {
        // Two ssh failures from one source: below AUTH_BF_WARN_THRESHOLD, so
        // detect_bruteforce stays silent — but the accumulator must still see 2.
        let failures = vec![
            failure("admin", Some("10.0.0.5"), "ssh", "10:00:00"),
            failure("admin", Some("10.0.0.5"), "ssh", "10:03:00"),
        ];
        assert!(
            detect_bruteforce(&failures).is_empty(),
            "precondition: sub-threshold"
        );
        let totals = service_failure_totals(&failures);
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].service, "ssh");
        assert_eq!(totals[0].count, 2);
        assert_eq!(totals[0].sources, vec!["10.0.0.5"]);
    }

    #[test]
    fn service_totals_collapse_logging_action_duplicates() {
        // One real failure emitted by two /system/logging actions (distinct
        // prefixes) must count once — same dedup the detector applies.
        let failures = vec![
            failure("admin", Some("10.0.0.5"), "api", "10:00:00"),
            failure_p("admin", Some("10.0.0.5"), "api", "10:00:00", "SYS-ERR:"),
        ];
        let totals = service_failure_totals(&failures);
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].count, 1, "logging-action echo is not a second failure");
    }

    #[test]
    fn service_totals_union_sources_and_hide_console() {
        let failures = vec![
            failure("admin", Some("10.0.0.5"), "ssh", "10:00:00"),
            failure("admin", Some("10.0.0.2"), "ssh", "10:01:00"),
            failure("root", None, "console", "10:02:00"),
        ];
        let mut totals = service_failure_totals(&failures);
        totals.sort_by(|a, b| a.service.cmp(&b.service));
        assert_eq!(totals.len(), 2);
        assert_eq!(totals[0].service, "console");
        assert_eq!(totals[0].count, 1, "console failures are counted");
        assert!(totals[0].sources.is_empty(), "…but 'local' is not a source IP");
        assert_eq!(totals[1].service, "ssh");
        assert_eq!(totals[1].count, 2);
        assert_eq!(totals[1].sources, vec!["10.0.0.2", "10.0.0.5"], "sorted, deduped");
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
        let entry = log("*1", "12:00:00", "login failure for user admin from 203.0.113.98 via api");
        let f = parse_login_failure(&entry).unwrap();
        assert_eq!(f.user, "admin");
        assert_eq!(f.src_ip.as_deref(), Some("203.0.113.98"));
        assert_eq!(f.service, "api");
    }

    /// Real RouterOS capture: RouterOS logging actions prepend severity prefixes.
    #[test]
    fn parses_prefixed_login_failure() {
        let entry = log(
            "*4",
            "12:00:00",
            "SYS-ERR: login failure for user drift-cve-test from 203.0.113.17 via rest-api",
        );
        let f = parse_login_failure(&entry).unwrap();
        assert_eq!(f.user, "drift-cve-test");
        assert_eq!(f.src_ip.as_deref(), Some("203.0.113.17"));
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
                failures.push(failure_p("admin", Some("203.0.113.17"), "rest-api", &t, prefix));
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

    /// The decoy probe. The sweep detector used to be gated on
    /// `signals.is_empty()`, so one throwaway address that crossed the
    /// per-source threshold switched the whole sweep detector off — an attacker
    /// disabling a detector for the price of one burner IP.
    #[test]
    fn decoy_source_cannot_suppress_the_sweep() {
        // 30 sources x 3 failures = 90, every source under the per-source bar.
        let mut failures = Vec::new();
        for src in 1..=30 {
            for i in 0..3 {
                failures.push(failure(
                    "admin",
                    Some(&format!("10.0.0.{src}")),
                    "api",
                    &format!("12:{src:02}:0{i}"),
                ));
            }
        }
        let signals = detect_bruteforce(&failures);
        assert_eq!(signals.len(), 1);
        assert!(signals[0].distributed);
        assert_eq!(signals[0].count, 90);
        assert_eq!(signals[0].sources.len(), 30);

        // The decoy: 5 failures from one throwaway address. This is the exact
        // input that used to make the 90-failure sweep vanish.
        for i in 0..5 {
            failures.push(failure("admin", Some("10.99.0.1"), "api", &format!("13:00:0{i}")));
        }
        let signals = detect_bruteforce(&failures);
        assert_eq!(signals.len(), 2, "both detectors must fire");
        let sweep = signals
            .iter()
            .find(|s| s.distributed)
            .expect("the 90-failure sweep must survive the decoy");
        assert_eq!(
            sweep.count, 95,
            "the decoy's failures stay inside the sweep total"
        );
        assert!(
            sweep.sources.iter().any(|s| s == "10.99.0.1"),
            "the decoy stays in the sweep's source list — subtracting it would be a \
             second off switch, since any IP pushed over the per-source threshold \
             would be removed from the sweep it belongs to"
        );
        assert_eq!(sweep.sources.len(), 31);
    }

    /// The two detectors answer different questions, so a cycle that trips both
    /// reports both. Neither is a gate on the other.
    #[test]
    fn per_source_and_sweep_are_independent() {
        // 6 failures from one source plus 3 each from four more: 18 across 5
        // sources, clearing the per-source bar and both distributed bars.
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
        assert_eq!(signals.len(), 2);
        assert_eq!(signals.iter().filter(|s| s.distributed).count(), 1);
        assert_eq!(signals.iter().filter(|s| !s.distributed).count(), 1);

        let sweep = signals.iter().find(|s| s.distributed).unwrap();
        assert_eq!(sweep.count, 18, "the loud source counts toward the sweep too");
        assert_eq!(sweep.sources.len(), 5);
        let per_source = signals.iter().find(|s| !s.distributed).unwrap();
        assert_eq!(per_source.subject, "auth:10.0.0.5:api");
        assert_eq!(per_source.count, 6);
    }

    /// How many narrow (per-source) signals each source contributes, keyed by
    /// source. A fixture where every value is 1 cannot exercise the roll-up
    /// accounting at all — see `alert_budget_rolls_up_beyond_cap`.
    fn narrow_signals_per_source(signals: &[BruteforceSignal]) -> BTreeMap<&str, usize> {
        let mut per_source: BTreeMap<&str, usize> = BTreeMap::new();
        for s in signals.iter().filter(|s| !s.distributed) {
            if let Some(src) = s.src_ip.as_deref() {
                *per_source.entry(src).or_default() += 1;
            }
        }
        per_source
    }

    /// No subject is inside its cooldown window — the shape every test that
    /// predates cooldown-aware planning assumes.
    fn no_cooldowns() -> BTreeSet<String> {
        BTreeSet::new()
    }

    /// A hand-built signal, for the cases `detect_bruteforce` cannot produce on
    /// demand: an all-warning cycle, or a specific subject already cooled.
    fn signal(subject: &str, src: Option<&str>, service: &str, count: usize, severity: &'static str) -> BruteforceSignal {
        BruteforceSignal {
            subject: subject.to_string(),
            src_ip: src.map(str::to_string),
            service: service.to_string(),
            services: vec![(service.to_string(), count)],
            sources: src.into_iter().map(str::to_string).collect(),
            count,
            users: vec!["admin".to_string()],
            severity,
            delay_bypass: false,
            distributed: false,
        }
    }

    /// A sweep covering `sources`, as `detect_bruteforce` builds it: no
    /// `src_ip` of its own, and every address in the batch listed.
    fn sweep(sources: &[&str], count: usize) -> BruteforceSignal {
        BruteforceSignal {
            subject: "auth:distributed".to_string(),
            src_ip: None,
            service: "api".to_string(),
            services: vec![("api".to_string(), count)],
            sources: sources.iter().map(|s| (*s).to_string()).collect(),
            count,
            users: vec!["admin".to_string()],
            severity: "critical",
            delay_bypass: false,
            distributed: true,
        }
    }

    /// A sweep inside its cooldown window must not absorb signals that are not.
    ///
    /// The regression this pins is a silent drop one layer below the partition
    /// identity. `evaluate_cycle` applies the `(rule_id, subject)` cooldown
    /// *after* the plan is built and simply skips a cooled alert — no delivery,
    /// no `record_alert_history`, no cooldown armed for anything else. Because
    /// `auth:distributed` is one constant subject on a 600s cooldown while the
    /// engine cycles every 60s, a plan that folded into it lost every folded
    /// burst nine cycles in ten, each of which had a clear cooldown of its own
    /// and would have alerted standalone. The log cursor had already advanced,
    /// so nothing rescanned them.
    ///
    /// Against the pre-fix selector (no `suppressed` parameter) the sweep is in
    /// `deliver`, `covered` holds both addresses, and both bursts land in
    /// `rolled_up` — this test fails on the first assertion.
    #[test]
    fn cooled_sweep_does_not_absorb_live_per_source_signals() {
        let signals = vec![
            sweep(&["10.0.0.1", "10.0.0.2"], 40),
            signal("auth:10.0.0.1:api", Some("10.0.0.1"), "api", 8, "warning"),
            signal("auth:10.0.0.2:api", Some("10.0.0.2"), "api", 8, "warning"),
        ];
        let suppressed: BTreeSet<String> = ["auth:distributed".to_string()].into();

        let plan = select_auth_alerts(&signals, AUTH_ALERT_BUDGET, &suppressed);

        assert!(
            plan.rolled_up.is_empty(),
            "a cooled sweep is delivered nowhere, so folding into it is a silent drop"
        );
        assert_eq!(plan.cooled, vec![0], "the sweep is the signal its cooldown suppressed");
        assert_eq!(
            plan.deliver,
            vec![1, 2],
            "both bursts have clear cooldowns and must alert on their own subjects"
        );
        assert_eq!(plan.over_budget(), 0);
        assert_eq!(
            plan.deliver.len() + plan.rolled_up.len() + plan.cooled.len() + plan.over_budget(),
            signals.len(),
            "the partition must still hold with a fourth bucket in play"
        );
    }

    /// A signal the cooldown will drop must not hold a delivery slot.
    ///
    /// Budget slots were handed out before the cooldown filter ran, so cooled
    /// subjects — which deliver nothing — could spend the whole budget and push
    /// signals that *would* have been delivered into `over_budget`. The
    /// ordering keys are severity, count and subject, all attacker-chosen, so
    /// the same subjects won the budget every cycle.
    ///
    /// Against the pre-fix selector the two cooled criticals sort first, fill
    /// `max_alerts = 2`, and both live signals are withheld.
    #[test]
    fn a_cooled_signal_does_not_consume_a_budget_slot() {
        let signals = vec![
            signal("auth:10.0.0.1:winbox", Some("10.0.0.1"), "winbox", 99, "critical"),
            signal("auth:10.0.0.2:winbox", Some("10.0.0.2"), "winbox", 98, "critical"),
            signal("auth:10.9.9.9:ssh", Some("10.9.9.9"), "ssh", 20, "critical"),
            signal("auth:10.9.9.8:ssh", Some("10.9.9.8"), "ssh", 19, "critical"),
        ];
        let suppressed: BTreeSet<String> = [
            "auth:10.0.0.1:winbox".to_string(),
            "auth:10.0.0.2:winbox".to_string(),
        ]
        .into();

        let plan = select_auth_alerts(&signals, 2, &suppressed);

        assert_eq!(plan.cooled, vec![0, 1]);
        assert_eq!(
            plan.deliver,
            vec![2, 3],
            "the budget belongs to the signals that can actually be delivered"
        );
        assert_eq!(
            plan.over_budget(),
            0,
            "nothing was withheld: the only competition for the two slots was cooled"
        );
    }

    /// The summary must be as loud as the loudest signal in the **cycle**, not
    /// the loudest one that happened to be delivered.
    ///
    /// Every other fixture that reaches `auth_budget_summary` has a critical in
    /// its delivered set — the sweep is hardcoded `critical` and sorts first —
    /// so the severity rule was indistinguishable from "highest delivered" and
    /// from a hardcoded `"critical"`. A budget of 0 separates them: nothing is
    /// delivered, so a delivered-only computation reports `warning` for a cycle
    /// that was entirely critical, hiding a critical behind the budget. The
    /// budget becomes config-driven in a later phase, which is exactly when a
    /// 0 arrives.
    #[test]
    fn budget_summary_severity_is_computed_over_the_whole_cycle() {
        let signals = vec![
            signal("auth:10.0.0.1:winbox", Some("10.0.0.1"), "winbox", 40, "critical"),
            signal("auth:10.0.0.2:winbox", Some("10.0.0.2"), "winbox", 30, "critical"),
        ];

        let plan = select_auth_alerts(&signals, 0, &no_cooldowns());

        assert!(plan.deliver.is_empty(), "a budget of 0 delivers nothing");
        assert_eq!(plan.over_budget(), 2, "and withholds everything");
        assert_eq!(
            auth_budget_summary(&plan, &signals).severity,
            "critical",
            "a summary quieter than what it stands in for hides a critical behind a budget"
        );
    }

    /// The other half of the same rule, and the only test that reaches the
    /// `warning` branch at all: a cycle with no critical in it must not be
    /// escalated. Guards the mirror-image shortcut of hardcoding `"critical"`,
    /// which every other fixture would accept.
    #[test]
    fn budget_summary_of_an_all_warning_cycle_stays_a_warning() {
        // One source over the per-source bar on several services, no sweep —
        // a real shape, and one that produces no critical signal.
        let signals: Vec<BruteforceSignal> = ["api", "ssh", "telnet", "ftp"]
            .iter()
            .map(|svc| signal(&format!("auth:10.4.0.1:{svc}"), Some("10.4.0.1"), svc, 6, "warning"))
            .collect();

        let plan = select_auth_alerts(&signals, 2, &no_cooldowns());

        assert_eq!(plan.deliver.len(), 2);
        assert_eq!(plan.over_budget(), 2, "the fixture must actually exceed the budget");
        assert_eq!(
            auth_budget_summary(&plan, &signals).severity,
            "warning",
            "no critical was detected this cycle, so the summary must not invent one"
        );
    }

    /// The summary body may only name surfaces that hold the withheld signals.
    ///
    /// It previously sent the operator to "the Advisories and Findings pages".
    /// There is no advisory route in the web crate, and `exploitation::evaluate`
    /// raises a finding only for a `strong` signal whose advisory covers the
    /// observed surface — `auth.login_failure_burst` is `corroborating`, so a
    /// withheld burst on ssh or winbox reaches neither page. Alert history is
    /// equally wrong: it records delivered alerts only.
    #[test]
    fn budget_summary_body_names_no_surface_that_lacks_the_data() {
        let signals = vec![
            signal("auth:10.0.0.1:ssh", Some("10.0.0.1"), "ssh", 40, "critical"),
            signal("auth:10.0.0.2:ssh", Some("10.0.0.2"), "ssh", 30, "critical"),
        ];
        let plan = select_auth_alerts(&signals, 1, &no_cooldowns());
        let body = auth_budget_summary(&plan, &signals).body;

        for absent in ["Advisories", "Findings", "advisory observation"] {
            assert!(
                !body.contains(absent),
                "body points at {absent}, which does not hold the withheld signals: {body}"
            );
        }
        // The locator has to be the real tracing target, not a word that merely
        // opens the message: `RUST_LOG` and structured-log filters match on the
        // target, so a body naming anything else sends the operator somewhere
        // empty — the same failure as the Advisories pointer, one level down.
        //
        // Two different guarantees, deliberately both asserted. The first is
        // construction: body and event both read AUTH_WITHHELD_LOG_TARGET, so
        // they cannot drift apart — but it compares the constant to itself and
        // can never fail on a value change, so it is not coverage and must not
        // be counted as any.
        assert!(
            body.contains(AUTH_WITHHELD_LOG_TARGET),
            "body must name the tracing target the withheld subjects are logged under: {body}"
        );
        // The second is the operational contract. A tracing target is something
        // operators bake into `RUST_LOG` and log-pipeline filters, so renaming
        // it silently breaks alerting runbooks in the field. The literal here
        // is the checkpoint: changing the target is allowed, changing it
        // without noticing is not.
        assert!(
            body.contains("auth_bruteforce"),
            "the withheld-signal log target is an operator-facing contract; if you meant to \
             rename it, update this literal and say so in the changelog: {body}"
        );
        assert!(
            body.contains("server log"),
            "the one surface that does hold them must be named: {body}"
        );
    }

    /// The polarity of the suppressed set, against a real store.
    ///
    /// Everything else in this module is handed the suppressed set already
    /// built, so a sign flip where it is *built* is invisible to all of them:
    /// inverting the condition delivers exactly the cooled alerts and silently
    /// suppresses exactly the deliverable ones, and a sabotage run confirmed
    /// the whole suite stays green through it. `is_cooled_down` returning
    /// `true` for "free to fire" is the trap — this pins the direction with a
    /// row that actually exists in the database.
    #[tokio::test]
    async fn suppressed_set_holds_the_cooled_subject_and_not_the_live_one() {
        let store = SwitchStore::new(std::path::Path::new(":memory:")).expect("in-memory store");
        let rule_id = 1;
        let cooldown_secs = 600;

        let signals = vec![
            signal("auth:10.7.0.1:api", Some("10.7.0.1"), "api", 9, "warning"),
            signal("auth:10.7.0.2:api", Some("10.7.0.2"), "api", 9, "warning"),
        ];

        // Nothing has fired yet: both subjects are free.
        let none = suppressed_auth_subjects(&store, rule_id, cooldown_secs, &signals).await;
        assert!(
            none.is_empty(),
            "a store with no cooldown rows must suppress nothing, got {none:?}"
        );

        // Arm the cooldown on the first subject only.
        update_cooldown(&store, rule_id, "auth:10.7.0.1:api").await;

        let after = suppressed_auth_subjects(&store, rule_id, cooldown_secs, &signals).await;
        assert!(
            after.contains("auth:10.7.0.1:api"),
            "the subject that just fired is inside its cooldown window and must be suppressed"
        );
        assert!(
            !after.contains("auth:10.7.0.2:api"),
            "the subject that never fired must stay deliverable — an inverted check suppresses \
             exactly this one and delivers the other"
        );
        assert_eq!(after.len(), 1);
    }

    /// The third severity mutation the two fixtures above cannot separate.
    ///
    /// `auth_budget_summary` documents "the highest severity the cycle
    /// produced, not the highest that happened to be withheld", but in both
    /// other fixtures the withheld set *is* the whole cycle or is uniformly
    /// warning, so `signals.iter()` and `plan.withheld.iter()` agree. This one
    /// separates them: the only critical is delivered and only warnings are
    /// withheld, so a withheld-only computation reports `warning` and the
    /// documented rule is false with the suite still green.
    #[test]
    fn budget_summary_severity_counts_delivered_criticals_too() {
        let signals = vec![
            signal("auth:10.5.0.1:winbox", Some("10.5.0.1"), "winbox", 40, "critical"),
            signal("auth:10.5.0.2:api", Some("10.5.0.2"), "api", 6, "warning"),
            signal("auth:10.5.0.3:api", Some("10.5.0.3"), "api", 5, "warning"),
        ];

        let plan = select_auth_alerts(&signals, 1, &no_cooldowns());

        assert_eq!(plan.deliver, vec![0], "the critical sorts first and takes the only slot");
        assert_eq!(plan.over_budget(), 2, "leaving two warnings withheld");
        assert!(
            plan.withheld.iter().all(|&i| signals[i].severity == "warning"),
            "the discriminating property: nothing critical is in the withheld set"
        );
        assert_eq!(
            auth_budget_summary(&plan, &signals).severity,
            "critical",
            "severity describes the cycle, not the withheld slice of it"
        );
    }

    /// Volume control lives at delivery. The budget may quieten the inbox; it
    /// may never reach back into detection.
    ///
    /// The fixture deliberately gives the folding sources **more than one
    /// service each**. Its previous shape gave every source exactly one
    /// service, which is the single shape where a plan that folds by *source
    /// name* still satisfies the partition identity — so the invariant below
    /// was asserted against a fixture that could not break it, and 24 signals
    /// went nowhere in production while the test stayed green. A fixture that
    /// cannot exercise the invariant it is paired with is not evidence, so the
    /// discriminating property is asserted outright before the plan is built.
    #[test]
    fn alert_budget_rolls_up_beyond_cap() {
        let mut failures = Vec::new();
        // 18 ordinary sources, each on TWO services (5 failures per group) —
        // 36 warnings a sweep body can stand in for.
        for src in 1..=18 {
            for (svc, hour) in [("api", 12), ("ssh", 13)] {
                for i in 0..5 {
                    failures.push(failure(
                        "admin",
                        Some(&format!("10.0.1.{src}")),
                        svc,
                        &format!("{hour}:{src:02}:0{i}"),
                    ));
                }
            }
        }
        // 12 heavy bursts (16 each) — critical, and not something a generic
        // sweep body reports, so they compete for the budget on their own.
        for src in 1..=12 {
            for i in 0..16 {
                failures.push(failure(
                    "admin",
                    Some(&format!("10.0.2.{src}")),
                    "winbox",
                    &format!("14:{i:02}:{src:02}"),
                ));
            }
        }
        let signals = detect_bruteforce(&failures);
        assert_eq!(signals.len(), 49, "48 per-source signals plus one sweep");
        // The property that makes this fixture able to catch the bug at all.
        assert!(
            narrow_signals_per_source(&signals).values().any(|&n| n > 1),
            "fixture must contain a source spanning several services, or the \
             partition identity below is asserted against a shape that cannot \
             violate it"
        );

        let plan = select_auth_alerts(&signals, 10, &no_cooldowns());
        assert!(
            plan.deliver.len() <= 10,
            "delivered {} exceeds the budget",
            plan.deliver.len()
        );
        assert!(
            plan.deliver.iter().any(|&i| signals[i].distributed),
            "broadest-first: the sweep describes the whole event and must be delivered"
        );
        assert!(!plan.rolled_up.is_empty(), "the ordinary bursts fold into the sweep");
        assert!(plan.over_budget() > 0, "the rest are withheld and summarised");
        // Nothing left detection: delivered + withheld + folded covers the set,
        // counted per signal — every one of the 36 warnings is folded, not the
        // 18 sources they came from.
        assert_eq!(plan.rolled_up.len(), 36, "one entry per folded signal");
        assert_eq!(
            plan.deliver.len() + plan.over_budget() + plan.rolled_up.len(),
            signals.len(),
            "deliver {} + withheld {} + folded {} must account for all {} signals",
            plan.deliver.len(),
            plan.over_budget(),
            plan.rolled_up.len(),
            signals.len(),
        );
        // And the summary alert that stands in for the withheld ones is not
        // quieter than the alerts it replaces.
        assert_eq!(auth_budget_summary(&plan, &signals).severity, "critical");
    }

    /// The reproducer for the accounting hole: one source, many services.
    ///
    /// Six qualifying `(source, service)` groups from a single address are six
    /// signals. Folding them by source name collapsed all six to one entry, so
    /// `deliver + rolled_up + over_budget` came to 2 of 7 — five signals were
    /// delivered nowhere and, because `over_budget` stayed 0, no "withheld"
    /// summary fired to say so.
    #[test]
    fn rollup_accounting_holds_when_one_source_spans_many_services() {
        let mut failures = Vec::new();
        // One loud source across six services, each group over the warning bar
        // and none of them critical — every one a roll-up candidate.
        for (svc, hour) in [
            ("api", 12),
            ("ssh", 13),
            ("telnet", 14),
            ("winbox", 15),
            ("ftp", 16),
            ("www", 17),
        ] {
            for i in 0..5 {
                failures.push(failure("admin", Some("10.3.0.1"), svc, &format!("{hour}:00:0{i}")));
            }
        }
        // Four quiet sources, each under the per-source bar, to carry the
        // sweep over its source threshold.
        for src in 2..=5 {
            for i in 0..3 {
                failures.push(failure(
                    "admin",
                    Some(&format!("10.3.0.{src}")),
                    "api",
                    &format!("18:0{src}:0{i}"),
                ));
            }
        }

        let signals = detect_bruteforce(&failures);
        assert_eq!(signals.len(), 7, "six per-source signals plus one sweep");
        assert_eq!(
            narrow_signals_per_source(&signals).get("10.3.0.1").copied(),
            Some(6),
            "the whole point of this fixture: one source, six signals"
        );

        let plan = select_auth_alerts(&signals, 10, &no_cooldowns());
        assert!(
            plan.deliver.iter().any(|&i| signals[i].distributed),
            "the sweep must be delivered for anything to fold into it"
        );
        assert_eq!(
            plan.deliver.len() + plan.rolled_up.len() + plan.over_budget(),
            signals.len(),
            "no signal may be unaccounted for: deliver {} + folded {} + withheld {} \
             accounts for {} of {} signals",
            plan.deliver.len(),
            plan.rolled_up.len(),
            plan.over_budget(),
            plan.deliver.len() + plan.rolled_up.len() + plan.over_budget(),
            signals.len(),
        );
        assert_eq!(plan.deliver.len(), 1, "only the sweep goes out");
        assert_eq!(plan.rolled_up.len(), 6, "all six narrow signals fold, not one source");
        assert_eq!(plan.over_budget(), 0, "the budget was never reached");

        // The identity above counts; this checks the buckets really are a
        // partition of the input and not two views of the same signals.
        let mut claimed: Vec<usize> =
            plan.deliver.iter().chain(plan.rolled_up.iter()).copied().collect();
        claimed.sort_unstable();
        let unique = {
            let mut u = claimed.clone();
            u.dedup();
            u
        };
        assert_eq!(claimed, unique, "no signal may be both delivered and folded");
        assert_eq!(
            claimed,
            (0..signals.len()).collect::<Vec<_>>(),
            "with nothing withheld the buckets must cover every index exactly once"
        );
        // And the six folded signals really are the one source's six services.
        let folded_sources = plan.rolled_up_sources(&signals);
        assert_eq!(folded_sources, vec!["10.3.0.1".to_string()]);
    }

    /// The partition identity across every shape of cycle, not just the one a
    /// hand-built fixture happens to produce.
    ///
    /// `deliver`, `rolled_up` and `over_budget` are the only three places a
    /// signal can end up, so their sizes must always add to the input. The
    /// "many sources, one service" shape is kept deliberately: it is the shape
    /// the old source-name accounting satisfied, and having it pass beside the
    /// shapes that broke it is the record of why it was never enough.
    #[test]
    fn no_signal_is_silently_dropped() {
        const SERVICES: [&str; 8] =
            ["api", "ssh", "telnet", "winbox", "ftp", "www", "api-ssl", "www-ssl"];
        // (label, sources, services per source, failures per group)
        let shapes: &[(&str, u32, usize, usize)] = &[
            ("one source, one service", 1, 1, 6),
            ("one source, many services", 1, 8, 6),
            ("many sources, one service", 12, 1, 6),
            ("many sources, many services", 9, 4, 6),
            ("many sources, many services, critical", 7, 3, 16),
            ("many sources, many services, mixed with quiet ones", 20, 2, 5),
        ];

        for &(label, sources, services, per_group) in shapes {
            let mut failures = Vec::new();
            for src in 1..=sources {
                for (s, service) in SERVICES.iter().take(services).enumerate() {
                    for i in 0..per_group {
                        failures.push(failure(
                            "admin",
                            Some(&format!("10.5.{src}.1")),
                            service,
                            &format!("{:02}:{i:02}:{src:02}", s + 1),
                        ));
                    }
                }
            }
            let signals = detect_bruteforce(&failures);
            assert!(!signals.is_empty(), "{label}: fixture produced no signals");

            for max_alerts in [0usize, 1, 3, 10, 1000] {
                let plan = select_auth_alerts(&signals, max_alerts, &no_cooldowns());
                assert_eq!(
                    plan.deliver.len() + plan.rolled_up.len() + plan.over_budget(),
                    signals.len(),
                    "{label} @ max={max_alerts}: deliver {} + folded {} + withheld {} \
                     accounts for {} of {} signals — the rest go nowhere",
                    plan.deliver.len(),
                    plan.rolled_up.len(),
                    plan.over_budget(),
                    plan.deliver.len() + plan.rolled_up.len() + plan.over_budget(),
                    signals.len(),
                );
                assert!(
                    plan.deliver.len() <= max_alerts,
                    "{label} @ max={max_alerts}: the budget must hold"
                );
                // Counts can add up while the same signal sits in two buckets;
                // check the indices really are disjoint and in range.
                let mut claimed: Vec<usize> =
                    plan.deliver.iter().chain(plan.rolled_up.iter()).copied().collect();
                claimed.sort_unstable();
                let mut unique = claimed.clone();
                unique.dedup();
                assert_eq!(
                    claimed, unique,
                    "{label} @ max={max_alerts}: a signal was both delivered and folded"
                );
                assert!(
                    claimed.iter().all(|&i| i < signals.len()),
                    "{label} @ max={max_alerts}: index out of range"
                );
            }
        }
    }

    /// A folded signal produces no alert of its own, so if the delivered sweep
    /// does not name its sources the operator never learns which hosts were
    /// involved. The sweep body used to say only "from multiple source IPs",
    /// leaving the appended roll-up sentence as the single place a folded
    /// address appeared anywhere.
    #[test]
    fn delivered_sweep_body_names_the_folded_sources() {
        let mut failures = Vec::new();
        // One source over the per-source bar on two services — it folds into
        // the sweep and gets no alert of its own.
        for (svc, hour) in [("api", 12), ("ssh", 13)] {
            for i in 0..5 {
                failures.push(failure("admin", Some("10.4.0.1"), svc, &format!("{hour}:00:0{i}")));
            }
        }
        for src in 2..=5 {
            for i in 0..3 {
                failures.push(failure(
                    "admin",
                    Some(&format!("10.4.0.{src}")),
                    "api",
                    &format!("14:0{src}:0{i}"),
                ));
            }
        }
        let signals = detect_bruteforce(&failures);
        let plan = select_auth_alerts(&signals, 10, &no_cooldowns());
        let sweep = plan
            .deliver
            .iter()
            .copied()
            .find(|&i| signals[i].distributed)
            .expect("the sweep must be delivered");
        assert!(!plan.rolled_up.is_empty(), "10.4.0.1 must have folded into the sweep");

        // The sweep's own body must name the sources it stands for — this is
        // what has to hold even if the roll-up sentence is absent or truncated.
        let plain = bruteforce_alert_body(&signals[sweep]);
        assert!(
            plain.contains("10.4.0.1"),
            "the sweep body must name the sources it covers, got: {plain}"
        );
        assert!(
            plain.contains("10.4.0.5"),
            "every source under the display bound must be named, got: {plain}"
        );

        // And the delivered body — body plus roll-up sentence — names it too.
        let delivered = delivered_bruteforce_body(&signals[sweep], &plan, &signals, true);
        assert!(
            delivered.contains("10.4.0.1"),
            "the folded source must appear in the delivered alert, got: {delivered}"
        );
        // Two folded signals, one host: the sentence must not report the
        // signal count as a number of source addresses.
        assert_eq!(plan.rolled_up.len(), 2, "api and ssh from the one source");
        assert!(
            delivered.contains("2 further signal(s), from 1 source IP(s)"),
            "signals and sources are counted separately, got: {delivered}"
        );
    }

    /// The source list in a body is attacker-sized: the number of addresses in
    /// a cycle is chosen by whoever is knocking. Naming them must therefore be
    /// bounded, or a 500-source sweep writes a 500-entry list into a push
    /// notification.
    #[test]
    fn delivered_sweep_body_bounds_the_source_list() {
        // 51 quiet sources, none over the per-source bar: one sweep, no narrow
        // signals. Equal-width octets so no address is a substring of another.
        let mut failures = Vec::new();
        let sources: Vec<String> = (10..=60).map(|n| format!("10.6.{n}.{n}")).collect();
        for (n, src) in sources.iter().enumerate() {
            for i in 0..3 {
                failures.push(failure("admin", Some(src), "api", &format!("12:{n:02}:0{i}")));
            }
        }
        let signals = detect_bruteforce(&failures);
        let sweep = signals.iter().find(|s| s.distributed).expect("sweep must fire");
        assert_eq!(sweep.sources.len(), 51);

        let body = bruteforce_alert_body(sweep);
        let named = sources.iter().filter(|s| body.contains(s.as_str())).count();
        assert!(
            named <= ALERT_BODY_SOURCE_LIST_MAX,
            "{named} sources named in one body — the list must stay bounded"
        );
        assert!(
            body.contains(&format!("+{} more", 51 - ALERT_BODY_SOURCE_LIST_MAX)),
            "the remainder must be counted rather than silently cut, got: {body}"
        );
        assert!(body.contains("51"), "the true source count must survive truncation");
    }

    /// The selector returns indices precisely so it cannot delete a signal:
    /// the caller still owns every one of them, whatever the plan says.
    #[test]
    fn selector_never_drops_a_signal_from_detection() {
        let mut failures = Vec::new();
        for src in 1..=12 {
            for i in 0..6 {
                failures.push(failure(
                    "admin",
                    Some(&format!("10.0.3.{src}")),
                    "api",
                    &format!("14:{src:02}:0{i}"),
                ));
            }
        }
        let signals = detect_bruteforce(&failures);
        assert!(signals.len() > 3);
        let before: Vec<(String, usize, bool)> = signals
            .iter()
            .map(|s| (s.subject.clone(), s.count, s.distributed))
            .collect();

        for max_alerts in [0usize, 1, 3, 100] {
            let plan = select_auth_alerts(&signals, max_alerts, &no_cooldowns());

            let after: Vec<(String, usize, bool)> = signals
                .iter()
                .map(|s| (s.subject.clone(), s.count, s.distributed))
                .collect();
            assert_eq!(before, after, "the input slice must come back untouched");
            assert_eq!(signals.len(), before.len(), "no signal may be removed");

            assert!(
                plan.deliver.iter().all(|&i| i < signals.len()),
                "every returned index must address a signal that exists"
            );
            let mut unique = plan.deliver.clone();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(unique.len(), plan.deliver.len(), "no index delivered twice");
            assert!(plan.deliver.len() <= max_alerts);
            assert!(plan.deliver.len() + plan.over_budget() <= signals.len());
        }
    }

    /// The cooldown is keyed `(rule_id, subject)`. A subject that moves with the
    /// cycle mints a new key every time, the cooldown never matches, and the
    /// storm the budget exists to stop comes back through the back door.
    #[test]
    fn budget_subject_is_stable_across_cycles() {
        fn heavy_cycle(sources: u32, third_octet: u32) -> Vec<BruteforceSignal> {
            let mut failures = Vec::new();
            for src in 1..=sources {
                for i in 0..16 {
                    failures.push(failure(
                        "admin",
                        Some(&format!("10.0.{third_octet}.{src}")),
                        "api",
                        &format!("15:{i:02}:{src:02}"),
                    ));
                }
            }
            detect_bruteforce(&failures)
        }

        let cycle_a = heavy_cycle(6, 4);
        let cycle_b = heavy_cycle(9, 5);
        let plan_a = select_auth_alerts(&cycle_a, 2, &no_cooldowns());
        let plan_b = select_auth_alerts(&cycle_b, 3, &no_cooldowns());
        assert!(plan_a.over_budget() > 0 && plan_b.over_budget() > 0);
        assert_ne!(
            plan_a.over_budget(), plan_b.over_budget(),
            "the two cycles must differ, or the test proves nothing"
        );

        let a = auth_budget_summary(&plan_a, &cycle_a);
        let b = auth_budget_summary(&plan_b, &cycle_b);
        assert_eq!(a.subject, b.subject, "two different cycles, one cooldown key");
        assert_eq!(a.subject, AUTH_BUDGET_SUBJECT);
        assert!(
            !a.subject.chars().any(|c| c.is_ascii_digit()),
            "no count or timestamp may reach the subject"
        );
        assert_eq!(a.title, b.title, "the title is a cooldown-adjacent surface too");
        assert_ne!(a.body, b.body, "the volatile numbers belong in the body");
        assert!(b.body.contains(&plan_b.over_budget().to_string()));
    }

    /// Regression: Drift authenticating with a stale stored password produces a
    /// same-second failure burst against its own router. Without the filter it
    /// reads as the concurrent-session bypass and Drift reports itself as an
    /// active intrusion.
    #[test]
    fn drift_own_credential_failures_are_excluded() {
        let failures: Vec<_> = (0..5)
            .map(|_| failure("drift-svc", Some("192.168.1.27"), "rest-api", "12:00:00"))
            .collect();
        // Own source is configured, so these really are Drift's own retries.
        let (kept, own) =
            split_own_credential_failures(&failures, "drift-svc", Some("192.168.1.27"));
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
            .map(|_| failure("Drift-SVC", Some("192.168.1.27"), "rest-api", "12:00:00"))
            .collect();
        let (kept, own) =
            split_own_credential_failures(&mixed_case, "drift-svc", Some("192.168.1.27"));
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
            .map(|_| failure("admin", Some("203.0.113.99"), "api", "12:00:00"))
            .collect();

        // Drift's own address is known and this is not it.
        let (kept, own) = split_own_credential_failures(&failures, "admin", Some("192.168.1.27"));
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
        assert!(!is_own_source(Some("192.168.1.27"), None));

        // Hostile: everything a `starts_with("127.")` test used to wave through.
        // The first is what a username of `admin from 127.0.0.1` produced before
        // the parser was hardened, and it is the shape that blinded detection.
        assert!(!is_own_source(Some("127.0.0.1 from 203.0.113.99"), None));
        assert!(!is_own_source(Some(" 127.0.0.1"), None));
        assert!(!is_own_source(Some("127.0.0.1x"), None));
        assert!(!is_own_source(Some("not-an-ip"), None));
        assert!(!is_own_source(Some(""), None));
        assert!(!is_own_source(Some("127.0.0.300"), None));

        // Configured: that address exactly. Not a console entry — Drift always
        // reaches the router over the network.
        assert!(is_own_source(Some("192.168.1.27"), Some("192.168.1.27")));
        assert!(!is_own_source(Some("192.168.1.28"), Some("192.168.1.27")));
        assert!(!is_own_source(None, Some("192.168.1.27")));

        // The same hostile shapes with an address configured: a value that only
        // *contains* the configured address is not the configured address, and
        // a configured value that is not an address matches nothing.
        assert!(!is_own_source(
            Some("192.168.1.27 from 203.0.113.99"),
            Some("192.168.1.27")
        ));
        assert!(!is_own_source(Some("192.168.1.27x"), Some("192.168.1.27")));
        assert!(!is_own_source(Some("192.168.1.27"), Some("drift.example.com")));
    }

    /// The full path a crafted attempt takes: raw log line → `parse_login_failure`
    /// → `split_own_credential_failures` → `detect_bruteforce`.
    ///
    /// RouterOS writes the attacker's username verbatim into the middle of the
    /// line, so an attempt as `admin from 127.0.0.1` logs as
    /// `login failure for user admin from 127.0.0.1 from 203.0.113.99 via api`.
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
                    "login failure for user admin from 127.0.0.1 from 203.0.113.99 via api",
                )
            })
            .collect();

        let parsed: Vec<LoginFailure> = entries.iter().filter_map(parse_login_failure).collect();
        assert_eq!(parsed.len(), 6, "every crafted line must still parse");
        assert_eq!(
            parsed[0].src_ip.as_deref(),
            Some("203.0.113.99"),
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
        assert_eq!(signals[0].src_ip.as_deref(), Some("203.0.113.99"));
        assert_eq!(signals[0].subject, "auth:203.0.113.99:api");
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
            "login failure for user admin via api from 203.0.113.99 via ssh",
        ))
        .unwrap();
        assert_eq!(f.user, "admin via api");
        assert_eq!(f.src_ip.as_deref(), Some("203.0.113.99"));
        assert_eq!(f.service, "ssh");

        // Both injected at once.
        let f = parse_login_failure(&log(
            "*2",
            "12:00:00",
            "login failure for user x from ::1 via console from 203.0.113.99 via api",
        ))
        .unwrap();
        assert_eq!(f.user, "x from ::1 via console");
        assert_eq!(f.src_ip.as_deref(), Some("203.0.113.99"));
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
    ///
    /// Do not "simplify" the `spread` set: since the sweep detector stopped
    /// being gated on the per-source branch, that one set produces *both* a
    /// per-source signal and a distributed one in the same batch, which is
    /// exactly the concurrent-branch case that needs covering here. Trimming it
    /// back to a single-branch input would quietly stop testing that.
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
