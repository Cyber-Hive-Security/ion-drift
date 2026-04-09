//! Alert storage — types and SwitchStore methods for alert rules, history,
//! delivery channels, cooldowns, and state cache.

use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::SwitchStore;

// ── Types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub event_type: String,
    pub severity_filter: Option<String>,
    pub vlan_filter: Option<String>,
    pub disposition_filter: Option<String>,
    pub verdict_filter: Option<String>,
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

// ── SwitchStore alert methods ──────────────────────────────────

impl SwitchStore {
    pub async fn get_alert_rules(&self) -> Result<Vec<AlertRule>, String> {
        let db = self.db().await;
        let mut stmt = db
            .prepare(
                "SELECT id, name, enabled, event_type, severity_filter, vlan_filter,
                        disposition_filter, verdict_filter, cooldown_seconds,
                        delivery_channels, created_at, updated_at
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
                    verdict_filter: row.get(7)?,
                    cooldown_seconds: row.get(8)?,
                    delivery_channels: row.get(9)?,
                    created_at: row.get(10)?,
                    updated_at: row.get(11)?,
                })
            })
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect failed: {e}"))
    }

    pub async fn get_alert_status(&self) -> Result<AlertStatus, String> {
        let db = self.db().await;
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
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AlertHistoryEntry>, String> {
        let db = self.db().await;
        let mut stmt = db
            .prepare(
                "SELECT id, rule_id, event_type, severity, device_mac, device_hostname,
                        device_ip, vlan_id, title, body, channels_attempted,
                        channels_succeeded, fired_at, anomaly_id
                 FROM alert_history ORDER BY fired_at DESC LIMIT ?1 OFFSET ?2",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map(params![limit, offset], |row| {
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

    pub async fn clear_alert_history(&self) -> Result<usize, String> {
        let db = self.db().await;
        db.execute("DELETE FROM alert_history", [])
            .map_err(|e| format!("delete failed: {e}"))
    }

    pub async fn get_delivery_channels(&self) -> Result<Vec<DeliveryChannelConfig>, String> {
        let db = self.db().await;
        let mut stmt = db
            .prepare("SELECT channel, enabled, config_json FROM alert_delivery_config ORDER BY channel")
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                let config_str: String = row.get(2)?;
                let config_json =
                    serde_json::from_str(&config_str).unwrap_or(serde_json::Value::Null);
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

    /// Insert a new alert rule. Returns the new rule's ID.
    pub async fn create_alert_rule(
        &self,
        name: &str,
        enabled: bool,
        event_type: &str,
        severity_filter: Option<&str>,
        vlan_filter: Option<&str>,
        disposition_filter: Option<&str>,
        verdict_filter: Option<&str>,
        cooldown_seconds: i64,
        delivery_channels: &str,
    ) -> Result<i64, String> {
        let db = self.db().await;
        db.execute(
            "INSERT INTO alert_rules (name, enabled, event_type, severity_filter, vlan_filter,
             disposition_filter, verdict_filter, cooldown_seconds, delivery_channels)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                name,
                enabled as i32,
                event_type,
                severity_filter,
                vlan_filter,
                disposition_filter,
                verdict_filter,
                cooldown_seconds,
                delivery_channels
            ],
        )
        .map_err(|e| format!("insert failed: {e}"))?;
        Ok(db.last_insert_rowid())
    }

    /// Dynamically update an alert rule. Only non-None fields are updated.
    /// Column names are hardcoded — no injection risk.
    pub async fn update_alert_rule(
        &self,
        id: i64,
        name: Option<&str>,
        enabled: Option<bool>,
        severity_filter: Option<&str>,
        vlan_filter: Option<&str>,
        disposition_filter: Option<&str>,
        verdict_filter: Option<&str>,
        cooldown_seconds: Option<i64>,
        delivery_channels: Option<&str>,
    ) -> Result<(), String> {
        let db = self.db().await;
        let mut sets = Vec::new();
        let mut p: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(v) = name {
            sets.push("name = ?");
            p.push(Box::new(v.to_string()));
        }
        if let Some(v) = enabled {
            sets.push("enabled = ?");
            p.push(Box::new(v as i32));
        }
        if let Some(v) = severity_filter {
            sets.push("severity_filter = ?");
            p.push(Box::new(v.to_string()));
        }
        if let Some(v) = vlan_filter {
            sets.push("vlan_filter = ?");
            p.push(Box::new(v.to_string()));
        }
        if let Some(v) = disposition_filter {
            sets.push("disposition_filter = ?");
            p.push(Box::new(v.to_string()));
        }
        if let Some(v) = verdict_filter {
            sets.push("verdict_filter = ?");
            p.push(Box::new(v.to_string()));
        }
        if let Some(v) = cooldown_seconds {
            sets.push("cooldown_seconds = ?");
            p.push(Box::new(v));
        }
        if let Some(v) = delivery_channels {
            sets.push("delivery_channels = ?");
            p.push(Box::new(v.to_string()));
        }

        if sets.is_empty() {
            return Ok(());
        }

        sets.push("updated_at = datetime('now')");
        let sql = format!("UPDATE alert_rules SET {} WHERE id = ?", sets.join(", "));
        p.push(Box::new(id));

        let refs: Vec<&dyn rusqlite::types::ToSql> = p.iter().map(|v| v.as_ref()).collect();
        db.execute(&sql, refs.as_slice())
            .map_err(|e| format!("update failed: {e}"))?;
        Ok(())
    }

    pub async fn delete_alert_rule(&self, id: i64) -> Result<(), String> {
        if id <= 10 {
            return Err("cannot delete default rules".into());
        }
        let db = self.db().await;
        let affected = db
            .execute("DELETE FROM alert_rules WHERE id = ?1", params![id])
            .map_err(|e| format!("delete failed: {e}"))?;
        if affected == 0 {
            return Err("rule not found".into());
        }
        Ok(())
    }

    pub async fn get_alert_state(&self, key: &str) -> Option<String> {
        let db = self.db().await;
        db.query_row(
            "SELECT value FROM alert_state_cache WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .ok()
    }

    pub async fn set_alert_state(&self, key: &str, value: &str) {
        let db = self.db().await;
        if let Err(e) = db.execute(
            "INSERT INTO alert_state_cache (key, value, updated_at) VALUES (?1, ?2, datetime('now'))
             ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = datetime('now')",
            params![key, value],
        ) {
            tracing::error!("failed to set alert state '{key}': {e}");
        }
    }

    pub async fn is_alert_cooled_down(
        &self,
        rule_id: i64,
        subject: &str,
        cooldown_secs: i64,
    ) -> bool {
        let db = self.db().await;
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM alert_cooldowns
                 WHERE rule_id = ?1 AND subject = ?2
                   AND last_fired_at > datetime('now', ?3)",
                params![rule_id, subject, format!("-{cooldown_secs} seconds")],
                |row| row.get(0),
            )
            .unwrap_or(0);
        count == 0
    }

    pub async fn update_alert_cooldown(&self, rule_id: i64, subject: &str) {
        let db = self.db().await;
        if let Err(e) = db.execute(
            "INSERT INTO alert_cooldowns (rule_id, subject, last_fired_at) VALUES (?1, ?2, datetime('now'))
             ON CONFLICT(rule_id, subject) DO UPDATE SET last_fired_at = datetime('now')",
            params![rule_id, subject],
        ) {
            tracing::error!("failed to update alert cooldown for rule {rule_id}: {e}");
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_alert_history(
        &self,
        rule_id: i64,
        event_type: &str,
        severity: &str,
        device_mac: Option<&str>,
        device_hostname: Option<&str>,
        device_ip: Option<&str>,
        vlan_id: Option<i64>,
        title: &str,
        body: &str,
        channels_attempted: &str,
        channels_succeeded: &str,
        anomaly_id: Option<i64>,
    ) {
        let db = self.db().await;
        if let Err(e) = db.execute(
            "INSERT INTO alert_history
                (rule_id, event_type, severity, device_mac, device_hostname, device_ip,
                 vlan_id, title, body, channels_attempted, channels_succeeded, anomaly_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                rule_id, event_type, severity, device_mac, device_hostname, device_ip,
                vlan_id, title, body, channels_attempted, channels_succeeded, anomaly_id,
            ],
        ) {
            tracing::error!("failed to record alert history: {e}");
        }
    }

    pub async fn update_delivery_channel(
        &self,
        channel: &str,
        enabled: Option<bool>,
        config_json: Option<&str>,
    ) -> Result<(), String> {
        let db = self.db().await;

        if let Some(en) = enabled {
            db.execute(
                "UPDATE alert_delivery_config SET enabled = ?1 WHERE channel = ?2",
                params![en as i32, channel],
            )
            .map_err(|e| format!("update enabled: {e}"))?;
        }

        if let Some(json_str) = config_json {
            db.execute(
                "UPDATE alert_delivery_config SET config_json = ?1 WHERE channel = ?2",
                params![json_str, channel],
            )
            .map_err(|e| format!("update config: {e}"))?;
        }

        Ok(())
    }
}
