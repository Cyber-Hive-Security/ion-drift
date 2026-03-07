//! Alerting engine — evaluates alert rules, enforces cooldowns, delivers notifications.
//!
//! Phase 1–4: anomaly_critical, anomaly_correlated, device_new, device_flagged, port_violation,
//! anomaly_warning, interface_down, device_offline, dhcp_pool_exhausted, firewall_drop_spike.
//! Delivery: ntfy, webhook, smtp.

use std::time::Duration;

use mikrotik_core::{BehaviorStore, SwitchStore};
use serde::{Deserialize, Serialize};

use crate::connection_store::ConnectionStore;
use crate::state::AppState;
use crate::task_supervisor::TaskSupervisor;

// ── Data types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub event_type: String,
    pub severity_filter: Option<String>,
    pub vlan_filter: Option<String>,
    pub disposition_filter: Option<String>,
    pub cooldown_seconds: i64,
    pub delivery_channels: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertHistoryEntry {
    pub id: i64,
    pub rule_id: i64,
    pub event_type: String,
    pub severity: String,
    pub device_mac: Option<String>,
    pub device_hostname: Option<String>,
    pub device_ip: Option<String>,
    pub vlan_id: Option<i64>,
    pub title: String,
    pub body: String,
    pub channels_attempted: String,
    pub channels_succeeded: String,
    pub fired_at: String,
    pub anomaly_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertStatus {
    pub enabled_rules: i64,
    pub total_rules: i64,
    pub last_check: Option<String>,
    pub alerts_fired_today: i64,
    pub unread_count_24h: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryChannelConfig {
    pub channel: String,
    pub enabled: bool,
    pub config_json: serde_json::Value,
}

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
}

// ── Alert store helpers ─────────────────────────────────────────

pub async fn get_alert_rules(store: &SwitchStore) -> Result<Vec<AlertRule>, String> {
    let db = store.db().await;
    let mut stmt = db
        .prepare(
            "SELECT id, name, enabled, event_type, severity_filter, vlan_filter,
                    disposition_filter, cooldown_seconds, delivery_channels,
                    created_at, updated_at
             FROM alert_rules ORDER BY id",
        )
        .map_err(|e| format!("prepare failed: {e}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(AlertRule {
                id: row.get(0)?,
                name: row.get(1)?,
                enabled: row.get::<_, i32>(2)? != 0,
                event_type: row.get(3)?,
                severity_filter: row.get(4)?,
                vlan_filter: row.get(5)?,
                disposition_filter: row.get(6)?,
                cooldown_seconds: row.get(7)?,
                delivery_channels: row.get(8)?,
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
            })
        })
        .map_err(|e| format!("query failed: {e}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("collect failed: {e}"))
}

pub async fn get_alert_status(store: &SwitchStore) -> Result<AlertStatus, String> {
    let db = store.db().await;
    let enabled: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM alert_rules WHERE enabled = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|e| format!("count failed: {e}"))?;
    let total: i64 = db
        .query_row("SELECT COUNT(*) FROM alert_rules", [], |row| row.get(0))
        .map_err(|e| format!("count failed: {e}"))?;
    let last_check: Option<String> = db
        .query_row(
            "SELECT value FROM alert_state_cache WHERE key = 'engine:last_check'",
            [],
            |row| row.get(0),
        )
        .ok();
    let today: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM alert_history WHERE fired_at >= datetime('now', '-1 day')",
            [],
            |row| row.get(0),
        )
        .map_err(|e| format!("count failed: {e}"))?;
    let unread_24h: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM alert_history WHERE fired_at >= datetime('now', '-24 hours')",
            [],
            |row| row.get(0),
        )
        .map_err(|e| format!("count failed: {e}"))?;
    Ok(AlertStatus {
        enabled_rules: enabled,
        total_rules: total,
        last_check,
        alerts_fired_today: today,
        unread_count_24h: unread_24h,
    })
}

pub async fn get_alert_history(
    store: &SwitchStore,
    limit: i64,
    offset: i64,
) -> Result<Vec<AlertHistoryEntry>, String> {
    let db = store.db().await;
    let mut stmt = db
        .prepare(
            "SELECT id, rule_id, event_type, severity, device_mac, device_hostname,
                    device_ip, vlan_id, title, body, channels_attempted,
                    channels_succeeded, fired_at, anomaly_id
             FROM alert_history ORDER BY fired_at DESC LIMIT ?1 OFFSET ?2",
        )
        .map_err(|e| format!("prepare failed: {e}"))?;
    let rows = stmt
        .query_map(rusqlite::params![limit, offset], |row| {
            Ok(AlertHistoryEntry {
                id: row.get(0)?,
                rule_id: row.get(1)?,
                event_type: row.get(2)?,
                severity: row.get(3)?,
                device_mac: row.get(4)?,
                device_hostname: row.get(5)?,
                device_ip: row.get(6)?,
                vlan_id: row.get(7)?,
                title: row.get(8)?,
                body: row.get(9)?,
                channels_attempted: row.get(10)?,
                channels_succeeded: row.get(11)?,
                fired_at: row.get(12)?,
                anomaly_id: row.get(13)?,
            })
        })
        .map_err(|e| format!("query failed: {e}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("collect failed: {e}"))
}

pub async fn clear_alert_history(store: &SwitchStore) -> Result<usize, String> {
    let db = store.db().await;
    db.execute("DELETE FROM alert_history", [])
        .map_err(|e| format!("delete failed: {e}"))
}

pub async fn get_delivery_channels(store: &SwitchStore) -> Result<Vec<DeliveryChannelConfig>, String> {
    let db = store.db().await;
    let mut stmt = db
        .prepare("SELECT channel, enabled, config_json FROM alert_delivery_config ORDER BY channel")
        .map_err(|e| format!("prepare failed: {e}"))?;
    let rows = stmt
        .query_map([], |row| {
            let config_str: String = row.get(2)?;
            let config_json = serde_json::from_str(&config_str).unwrap_or(serde_json::Value::Null);
            Ok(DeliveryChannelConfig {
                channel: row.get(0)?,
                enabled: row.get::<_, i32>(1)? != 0,
                config_json,
            })
        })
        .map_err(|e| format!("query failed: {e}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("collect failed: {e}"))
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
    pub cooldown_seconds: Option<i64>,
    pub delivery_channels: Option<String>,
}

pub async fn create_rule(store: &SwitchStore, req: CreateRuleRequest) -> Result<AlertRule, String> {
    let db = store.db().await;
    let enabled = req.enabled.unwrap_or(true) as i32;
    let cooldown = req.cooldown_seconds.unwrap_or(300);
    let channels = req.delivery_channels.as_deref().unwrap_or(r#"["ntfy"]"#);

    db.execute(
        "INSERT INTO alert_rules (name, enabled, event_type, severity_filter, vlan_filter,
         disposition_filter, cooldown_seconds, delivery_channels)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            req.name, enabled, req.event_type, req.severity_filter,
            req.vlan_filter, req.disposition_filter, cooldown, channels
        ],
    ).map_err(|e| format!("insert failed: {e}"))?;

    let id = db.last_insert_rowid();
    drop(db);
    // Return the created rule
    let rules = get_alert_rules(store).await?;
    rules.into_iter().find(|r| r.id == id).ok_or("rule not found after insert".into())
}

pub async fn update_rule(store: &SwitchStore, id: i64, req: UpdateRuleRequest) -> Result<(), String> {
    let db = store.db().await;
    let mut sets = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    if let Some(ref name) = req.name {
        sets.push("name = ?");
        params.push(Box::new(name.clone()));
    }
    if let Some(enabled) = req.enabled {
        sets.push("enabled = ?");
        params.push(Box::new(enabled as i32));
    }
    if let Some(ref sf) = req.severity_filter {
        sets.push("severity_filter = ?");
        params.push(Box::new(sf.clone()));
    }
    if let Some(ref vf) = req.vlan_filter {
        sets.push("vlan_filter = ?");
        params.push(Box::new(vf.clone()));
    }
    if let Some(ref df) = req.disposition_filter {
        sets.push("disposition_filter = ?");
        params.push(Box::new(df.clone()));
    }
    if let Some(cooldown) = req.cooldown_seconds {
        sets.push("cooldown_seconds = ?");
        params.push(Box::new(cooldown));
    }
    if let Some(ref channels) = req.delivery_channels {
        sets.push("delivery_channels = ?");
        params.push(Box::new(channels.clone()));
    }

    if sets.is_empty() {
        return Ok(());
    }

    sets.push("updated_at = datetime('now')");
    let sql = format!("UPDATE alert_rules SET {} WHERE id = ?", sets.join(", "));
    params.push(Box::new(id));

    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    db.execute(&sql, param_refs.as_slice())
        .map_err(|e| format!("update failed: {e}"))?;
    Ok(())
}

pub async fn delete_rule(store: &SwitchStore, id: i64) -> Result<(), String> {
    let db = store.db().await;

    // Check if it's a default rule (id <= 10 are default-seeded)
    if id <= 10 {
        return Err("cannot delete default rules".into());
    }

    let affected = db.execute("DELETE FROM alert_rules WHERE id = ?1", rusqlite::params![id])
        .map_err(|e| format!("delete failed: {e}"))?;
    if affected == 0 {
        return Err("rule not found".into());
    }
    Ok(())
}

// ── State cache helpers ─────────────────────────────────────────

async fn get_state(store: &SwitchStore, key: &str) -> Option<String> {
    let db = store.db().await;
    db.query_row(
        "SELECT value FROM alert_state_cache WHERE key = ?1",
        rusqlite::params![key],
        |row| row.get(0),
    )
    .ok()
}

async fn set_state(store: &SwitchStore, key: &str, value: &str) {
    let db = store.db().await;
    if let Err(e) = db.execute(
        "INSERT INTO alert_state_cache (key, value, updated_at) VALUES (?1, ?2, datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = datetime('now')",
        rusqlite::params![key, value],
    ) {
        tracing::error!("failed to set alert state '{key}': {e}");
    }
}

// ── Cooldown check ──────────────────────────────────────────────

async fn is_cooled_down(store: &SwitchStore, rule_id: i64, subject: &str, cooldown_secs: i64) -> bool {
    let db = store.db().await;
    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM alert_cooldowns
             WHERE rule_id = ?1 AND subject = ?2
               AND last_fired_at > datetime('now', ?3)",
            rusqlite::params![rule_id, subject, format!("-{cooldown_secs} seconds")],
            |row| row.get(0),
        )
        .unwrap_or(0);
    count == 0
}

async fn update_cooldown(store: &SwitchStore, rule_id: i64, subject: &str) {
    let db = store.db().await;
    if let Err(e) = db.execute(
        "INSERT INTO alert_cooldowns (rule_id, subject, last_fired_at) VALUES (?1, ?2, datetime('now'))
         ON CONFLICT(rule_id, subject) DO UPDATE SET last_fired_at = datetime('now')",
        rusqlite::params![rule_id, subject],
    ) {
        tracing::error!("failed to update alert cooldown for rule {rule_id}: {e}");
    }
}

// ── Record alert history ────────────────────────────────────────

async fn record_alert(store: &SwitchStore, alert: &PendingAlert, attempted: &[String], succeeded: &[String]) {
    let db = store.db().await;
    if let Err(e) = db.execute(
        "INSERT INTO alert_history
            (rule_id, event_type, severity, device_mac, device_hostname, device_ip,
             vlan_id, title, body, channels_attempted, channels_succeeded, anomaly_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        rusqlite::params![
            alert.rule_id,
            alert.event_type,
            alert.severity,
            alert.device_mac,
            alert.device_hostname,
            alert.device_ip,
            alert.vlan_id,
            alert.title,
            alert.body,
            serde_json::to_string(attempted).unwrap_or_default(),
            serde_json::to_string(succeeded).unwrap_or_default(),
            alert.anomaly_id,
        ],
    ) {
        tracing::error!("failed to record alert history: {e}");
    }
}

// ── ntfy delivery ───────────────────────────────────────────────

async fn deliver_ntfy(
    http: &reqwest::Client,
    config: &serde_json::Value,
    title: &str,
    body: &str,
    severity: &str,
) -> Result<(), String> {
    let url = config.get("url").and_then(|v| v.as_str()).unwrap_or("https://ntfy.sh");
    let topic = config.get("topic").and_then(|v| v.as_str()).unwrap_or("");
    let token = config.get("token").and_then(|v| v.as_str()).unwrap_or("");

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
) -> Result<(), String> {
    let url = config.get("url").and_then(|v| v.as_str()).unwrap_or("");
    let secret = config.get("secret").and_then(|v| v.as_str()).unwrap_or("");

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
    let db = store.db().await;

    if let Some(en) = enabled {
        db.execute(
            "UPDATE alert_delivery_config SET enabled = ?1 WHERE channel = ?2",
            rusqlite::params![en as i32, channel],
        )
        .map_err(|e| format!("update enabled: {e}"))?;
    }

    if let Some(cfg) = config_json {
        let json_str = serde_json::to_string(&cfg).map_err(|e| format!("json encode: {e}"))?;
        db.execute(
            "UPDATE alert_delivery_config SET config_json = ?1 WHERE channel = ?2",
            rusqlite::params![json_str, channel],
        )
        .map_err(|e| format!("update config: {e}"))?;
    }

    Ok(())
}

/// Send a test notification to a channel.
pub async fn test_channel(
    http: &reqwest::Client,
    store: &SwitchStore,
    channel: &str,
    smtp_password: Option<&str>,
) -> Result<(), String> {
    let channels = get_delivery_channels(store).await?;
    let config = channels.iter().find(|c| c.channel == channel)
        .ok_or_else(|| format!("unknown channel: {channel}"))?;

    let title = "Ion Drift — Test Alert";
    let body = &format!(
        "This is a test notification from Ion Drift. If you received this, your {channel} delivery channel is configured correctly."
    );

    match channel {
        "ntfy" => deliver_ntfy(http, &config.config_json, title, body, "info").await,
        "webhook" => deliver_webhook(http, &config.config_json, title, body, "info", None).await,
        "smtp" => deliver_smtp(&config.config_json, smtp_password, title, body).await,
        _ => Err(format!("unknown channel '{channel}'")),
    }
}

// ── Alert engine evaluation cycle ───────────────────────────────

async fn evaluate_cycle(
    state: &AppState,
    http: &reqwest::Client,
    smtp_password: Option<&str>,
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
                collect_new_device_alerts(switch_store, rule, &mut pending_alerts).await;
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
            _ => {}
        }
    }

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
                    "ntfy" => deliver_ntfy(http, &ch_config.config_json, &alert.title, &alert.body, &alert.severity).await,
                    "webhook" => deliver_webhook(http, &ch_config.config_json, &alert.title, &alert.body, &alert.severity, Some(alert)).await,
                    "smtp" => deliver_smtp(&ch_config.config_json, smtp_password, &alert.title, &alert.body).await,
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
            .get_anomalies(Some("pending"), Some("critical"), None, Some(50))
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
            });
        }

        if max_id > last_id {
            set_state(switch_store, "anomaly_link:last_id", &max_id.to_string()).await;
        }
    }
}

async fn collect_new_device_alerts(
    switch_store: &SwitchStore,
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
            .map(|v| mikrotik_core::behavior::vlan_name(v))
            .unwrap_or("Unknown");

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
        .get_anomalies(Some("pending"), Some("warning"), None, Some(50))
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
            });
        }
    }
}

async fn collect_dhcp_pool_alerts(state: &AppState, rule: &AlertRule, alerts: &mut Vec<PendingAlert>) {
    let channels = parse_channels(&rule.delivery_channels);

    // Fetch DHCP servers, pools, and leases from the router
    let (servers_res, pools_res, leases_res) = tokio::join!(
        state.mikrotik.dhcp_servers(),
        state.mikrotik.ip_pools(),
        state.mikrotik.dhcp_leases(),
    );

    let servers = match servers_res {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("alerting: dhcp_pool_exhausted: failed to fetch DHCP servers: {e}");
            return;
        }
    };
    let pools = match pools_res {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("alerting: dhcp_pool_exhausted: failed to fetch IP pools: {e}");
            return;
        }
    };
    let leases = match leases_res {
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
        });
    }
}

fn parse_channels(json: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(json).unwrap_or_default()
}

// ── Background task ─────────────────────────────────────────────

pub fn spawn_alert_engine(supervisor: &TaskSupervisor, state: AppState) {
    supervisor.spawn("alert_engine", move || {
        let state = state.clone();
        Box::pin(async move {
        // 30 second startup delay
        tokio::time::sleep(Duration::from_secs(30)).await;
        tracing::info!("alert engine starting");

        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;

            // Resolve SMTP password from encrypted secrets if available
            let smtp_pw = if let Some(ref sm) = state.secrets_manager {
                let sm_guard = sm.read().await;
                match sm_guard.decrypt_secret("smtp_password").await {
                    Ok(Some(secret)) => {
                        use secrecy::ExposeSecret;
                        Some(secret.expose_secret().to_string())
                    }
                    _ => None,
                }
            } else {
                None
            };

            evaluate_cycle(
                &state,
                &state.http_client,
                smtp_pw.as_deref(),
            )
            .await;
        }
    })});
}
