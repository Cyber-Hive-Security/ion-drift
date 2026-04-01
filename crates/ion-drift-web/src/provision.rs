use serde::{Deserialize, Serialize};

use mikrotik_core::{
    CreateFilterRule, CreateLoggingAction, CreateLoggingRule, MikrotikClient,
};
use mikrotik_core::resources::firewall::CreateMangleRule;

// ── Types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionConfig {
    pub wan_interface: String,
    pub syslog_host: String,
    #[serde(default = "default_syslog_port")]
    pub syslog_port: u16,
    pub router_source_ip: String,
}

fn default_syslog_port() -> u16 {
    5514
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionPlan {
    pub items: Vec<ProvisionItem>,
    pub summary: PlanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionItem {
    pub id: String,
    pub category: String,
    pub action: String,
    pub title: String,
    pub description: String,
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanSummary {
    pub create: usize,
    pub skip: usize,
    pub update: usize,
    pub total_mangle: usize,
    pub total_syslog: usize,
    pub total_firewall: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplyResult {
    pub results: Vec<ApplyItemResult>,
    pub succeeded: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplyItemResult {
    pub id: String,
    pub title: String,
    pub success: bool,
    pub error: Option<String>,
}

// ── Constants ──────────────────────────────────────────────────────

const COMMENT_PREFIX: &str = "ion-drift-flow:";
const ACTION_NAME: &str = "ion-drift";
const LOG_PREFIX: &str = "ION";
const FW_COMMENT: &str = "ion-drift syslog capture";

// ── Plan Generation ────────────────────────────────────────────────

pub async fn generate_plan(
    client: &MikrotikClient,
    config: &ProvisionConfig,
) -> Result<ProvisionPlan, anyhow::Error> {
    // Fetch all relevant state from the router in parallel-ish fashion
    let vlans = client.vlan_interfaces().await?;
    let existing_mangle = client.firewall_mangle_rules().await?;
    let existing_actions = client.system_logging_actions().await?;
    let existing_log_rules = client.system_logging_rules().await?;
    let existing_filter_rules = client.firewall_filter_rules().await?;

    let vlan_names: Vec<String> = vlans.iter().map(|v| v.name.clone()).collect();

    // Collect existing ion-drift mangle comments
    let existing_comments: Vec<&str> = existing_mangle
        .iter()
        .filter_map(|r| r.comment.as_deref())
        .filter(|c| c.starts_with(COMMENT_PREFIX))
        .collect();

    let mut items = Vec::new();

    // ── Mangle rules: VLAN-to-VLAN pairs ───────────────────────────
    for src in &vlan_names {
        for dst in &vlan_names {
            if src == dst {
                continue;
            }
            let comment = format!("{COMMENT_PREFIX}{src}>{dst}");
            let id = format!("mangle-{src}>{dst}");
            if existing_comments.contains(&comment.as_str()) {
                items.push(ProvisionItem {
                    id,
                    category: "mangle_rule".into(),
                    action: "skip".into(),
                    title: format!("Flow counter: {src} -> {dst}"),
                    description: format!("Mangle passthrough rule already exists for {src} -> {dst}"),
                    detail: serde_json::json!({
                        "chain": "forward",
                        "action": "passthrough",
                        "in-interface": src,
                        "out-interface": dst,
                        "comment": comment,
                    }),
                });
            } else {
                items.push(ProvisionItem {
                    id,
                    category: "mangle_rule".into(),
                    action: "create".into(),
                    title: format!("Flow counter: {src} -> {dst}"),
                    description: format!(
                        "Create mangle passthrough rule to count traffic from {src} to {dst}"
                    ),
                    detail: serde_json::json!({
                        "chain": "forward",
                        "action": "passthrough",
                        "in-interface": src,
                        "out-interface": dst,
                        "comment": comment,
                    }),
                });
            }
        }
    }

    // ── Mangle rules: WAN <-> VLAN pairs ───────────────────────────
    let wan = &config.wan_interface;
    for vlan in &vlan_names {
        // WAN -> VLAN
        let comment = format!("{COMMENT_PREFIX}{wan}>{vlan}");
        let id = format!("mangle-{wan}>{vlan}");
        if existing_comments.contains(&comment.as_str()) {
            items.push(ProvisionItem {
                id,
                category: "mangle_rule".into(),
                action: "skip".into(),
                title: format!("Flow counter: {wan} -> {vlan}"),
                description: format!("Mangle passthrough rule already exists for {wan} -> {vlan}"),
                detail: serde_json::json!({
                    "chain": "forward",
                    "action": "passthrough",
                    "in-interface": wan,
                    "out-interface": vlan,
                    "comment": comment,
                }),
            });
        } else {
            items.push(ProvisionItem {
                id,
                category: "mangle_rule".into(),
                action: "create".into(),
                title: format!("Flow counter: {wan} -> {vlan}"),
                description: format!(
                    "Create mangle passthrough rule to count inbound traffic from {wan} to {vlan}"
                ),
                detail: serde_json::json!({
                    "chain": "forward",
                    "action": "passthrough",
                    "in-interface": wan,
                    "out-interface": vlan,
                    "comment": comment,
                }),
            });
        }

        // VLAN -> WAN
        let comment = format!("{COMMENT_PREFIX}{vlan}>{wan}");
        let id = format!("mangle-{vlan}>{wan}");
        if existing_comments.contains(&comment.as_str()) {
            items.push(ProvisionItem {
                id,
                category: "mangle_rule".into(),
                action: "skip".into(),
                title: format!("Flow counter: {vlan} -> {wan}"),
                description: format!("Mangle passthrough rule already exists for {vlan} -> {wan}"),
                detail: serde_json::json!({
                    "chain": "forward",
                    "action": "passthrough",
                    "in-interface": vlan,
                    "out-interface": wan,
                    "comment": comment,
                }),
            });
        } else {
            items.push(ProvisionItem {
                id,
                category: "mangle_rule".into(),
                action: "create".into(),
                title: format!("Flow counter: {vlan} -> {wan}"),
                description: format!(
                    "Create mangle passthrough rule to count outbound traffic from {vlan} to {wan}"
                ),
                detail: serde_json::json!({
                    "chain": "forward",
                    "action": "passthrough",
                    "in-interface": vlan,
                    "out-interface": wan,
                    "comment": comment,
                }),
            });
        }
    }

    // ── Syslog action ──────────────────────────────────────────────
    let existing_action = existing_actions.iter().find(|a| a.name == ACTION_NAME);
    match existing_action {
        Some(action) => {
            let remote_matches = action.remote.as_deref() == Some(&config.syslog_host);
            let port_matches = action.remote_port == Some(config.syslog_port as u32);
            let src_matches = action.src_address.as_deref() == Some(&config.router_source_ip);

            if remote_matches && port_matches && src_matches {
                items.push(ProvisionItem {
                    id: "syslog-action".into(),
                    category: "syslog_action".into(),
                    action: "skip".into(),
                    title: format!("Syslog action: {ACTION_NAME}"),
                    description: format!(
                        "Remote logging action '{ACTION_NAME}' already configured correctly -> {}:{}",
                        config.syslog_host, config.syslog_port
                    ),
                    detail: serde_json::json!({
                        "name": ACTION_NAME,
                        "target": "remote",
                        "remote": config.syslog_host,
                        "remote-port": config.syslog_port,
                        "src-address": config.router_source_ip,
                    }),
                });
            } else {
                items.push(ProvisionItem {
                    id: "syslog-action".into(),
                    category: "syslog_action".into(),
                    action: "update".into(),
                    title: format!("Syslog action: {ACTION_NAME}"),
                    description: format!(
                        "Update remote logging action '{ACTION_NAME}': remote {}:{} src {} (current: remote {:?}:{:?} src {:?})",
                        config.syslog_host, config.syslog_port, config.router_source_ip,
                        action.remote, action.remote_port, action.src_address,
                    ),
                    detail: serde_json::json!({
                        "name": ACTION_NAME,
                        "target": "remote",
                        "remote": config.syslog_host,
                        "remote-port": config.syslog_port,
                        "src-address": config.router_source_ip,
                        "existing_id": action.id,
                        "old_remote": action.remote,
                        "old_remote_port": action.remote_port,
                        "old_src_address": action.src_address,
                    }),
                });
            }
        }
        None => {
            items.push(ProvisionItem {
                id: "syslog-action".into(),
                category: "syslog_action".into(),
                action: "create".into(),
                title: format!("Syslog action: {ACTION_NAME}"),
                description: format!(
                    "Create remote logging action '{ACTION_NAME}' -> {}:{} (src: {})",
                    config.syslog_host, config.syslog_port, config.router_source_ip
                ),
                detail: serde_json::json!({
                    "name": ACTION_NAME,
                    "target": "remote",
                    "remote": config.syslog_host,
                    "remote-port": config.syslog_port,
                    "src-address": config.router_source_ip,
                    "remote-log-format": "bsd-syslog",
                }),
            });
        }
    }

    // ── Syslog logging rule ────────────────────────────────────────
    let has_log_rule = existing_log_rules
        .iter()
        .any(|r| r.action == ACTION_NAME && r.topics.contains("firewall"));

    if has_log_rule {
        items.push(ProvisionItem {
            id: "syslog-rule".into(),
            category: "syslog_rule".into(),
            action: "skip".into(),
            title: "Logging rule: firewall -> ion-drift".into(),
            description: format!(
                "Logging rule routing topic 'firewall' to action '{ACTION_NAME}' already exists"
            ),
            detail: serde_json::json!({
                "topics": "firewall",
                "action": ACTION_NAME,
            }),
        });
    } else {
        items.push(ProvisionItem {
            id: "syslog-rule".into(),
            category: "syslog_rule".into(),
            action: "create".into(),
            title: "Logging rule: firewall -> ion-drift".into(),
            description: format!(
                "Create logging rule to route topic 'firewall' to action '{ACTION_NAME}'"
            ),
            detail: serde_json::json!({
                "topics": "firewall",
                "action": ACTION_NAME,
            }),
        });
    }

    // ── Firewall log rules ─────────────────────────────────────────
    let ion_log_rules: Vec<_> = existing_filter_rules
        .iter()
        .filter(|r| r.action == "log" && r.log_prefix.as_deref() == Some(LOG_PREFIX))
        .collect();

    let has_forward_log = ion_log_rules.iter().any(|r| r.chain == "forward");
    let has_input_log = ion_log_rules.iter().any(|r| r.chain == "input");

    // Forward chain log rule
    if has_forward_log {
        items.push(ProvisionItem {
            id: "firewall-log-forward".into(),
            category: "firewall_log".into(),
            action: "skip".into(),
            title: "Firewall log: forward chain".into(),
            description: format!(
                "Firewall log rule for new connections in forward chain (prefix '{LOG_PREFIX}') already exists"
            ),
            detail: serde_json::json!({
                "chain": "forward",
                "action": "log",
                "connection-state": "new",
                "log-prefix": LOG_PREFIX,
                "comment": FW_COMMENT,
            }),
        });
    } else {
        items.push(ProvisionItem {
            id: "firewall-log-forward".into(),
            category: "firewall_log".into(),
            action: "create".into(),
            title: "Firewall log: forward chain".into(),
            description: format!(
                "Create firewall rule to log new connections in forward chain with prefix '{LOG_PREFIX}'"
            ),
            detail: serde_json::json!({
                "chain": "forward",
                "action": "log",
                "connection-state": "new",
                "log": "true",
                "log-prefix": LOG_PREFIX,
                "comment": FW_COMMENT,
            }),
        });
    }

    // Input chain log rule
    if has_input_log {
        items.push(ProvisionItem {
            id: "firewall-log-input".into(),
            category: "firewall_log".into(),
            action: "skip".into(),
            title: "Firewall log: input chain".into(),
            description: format!(
                "Firewall log rule for new connections in input chain (prefix '{LOG_PREFIX}') already exists"
            ),
            detail: serde_json::json!({
                "chain": "input",
                "action": "log",
                "connection-state": "new",
                "log-prefix": LOG_PREFIX,
                "comment": FW_COMMENT,
            }),
        });
    } else {
        items.push(ProvisionItem {
            id: "firewall-log-input".into(),
            category: "firewall_log".into(),
            action: "create".into(),
            title: "Firewall log: input chain".into(),
            description: format!(
                "Create firewall rule to log new connections in input chain with prefix '{LOG_PREFIX}'"
            ),
            detail: serde_json::json!({
                "chain": "input",
                "action": "log",
                "connection-state": "new",
                "log": "true",
                "log-prefix": LOG_PREFIX,
                "comment": FW_COMMENT,
            }),
        });
    }

    // ── Compute summary ────────────────────────────────────────────
    let create = items.iter().filter(|i| i.action == "create").count();
    let skip = items.iter().filter(|i| i.action == "skip").count();
    let update = items.iter().filter(|i| i.action == "update").count();
    let total_mangle = items.iter().filter(|i| i.category == "mangle_rule").count();
    let total_syslog = items
        .iter()
        .filter(|i| i.category == "syslog_action" || i.category == "syslog_rule")
        .count();
    let total_firewall = items
        .iter()
        .filter(|i| i.category == "firewall_log")
        .count();

    Ok(ProvisionPlan {
        items,
        summary: PlanSummary {
            create,
            skip,
            update,
            total_mangle,
            total_syslog,
            total_firewall,
        },
    })
}

// ── Plan Application ───────────────────────────────────────────────

pub async fn apply_plan(
    client: &MikrotikClient,
    config: &ProvisionConfig,
    item_ids: &[String],
) -> Result<ApplyResult, anyhow::Error> {
    // Regenerate the plan to get current state
    let plan = generate_plan(client, config).await?;

    // Filter to only requested items that need action
    let selected: Vec<&ProvisionItem> = plan
        .items
        .iter()
        .filter(|item| item_ids.contains(&item.id) && item.action != "skip")
        .collect();

    let mut results = Vec::new();
    let mut succeeded = 0usize;
    let mut failed = 0usize;

    for item in &selected {
        let result = apply_item(client, config, item).await;
        match result {
            Ok(()) => {
                succeeded += 1;
                results.push(ApplyItemResult {
                    id: item.id.clone(),
                    title: item.title.clone(),
                    success: true,
                    error: None,
                });
            }
            Err(e) => {
                failed += 1;
                results.push(ApplyItemResult {
                    id: item.id.clone(),
                    title: item.title.clone(),
                    success: false,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    Ok(ApplyResult {
        results,
        succeeded,
        failed,
    })
}

async fn apply_item(
    client: &MikrotikClient,
    config: &ProvisionConfig,
    item: &ProvisionItem,
) -> Result<(), anyhow::Error> {
    match item.category.as_str() {
        "mangle_rule" => {
            let in_iface = item.detail["in-interface"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing in-interface in detail"))?;
            let out_iface = item.detail["out-interface"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing out-interface in detail"))?;
            let comment = item.detail["comment"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing comment in detail"))?;

            client
                .create_mangle_rule(&CreateMangleRule {
                    chain: "forward".into(),
                    action: "passthrough".into(),
                    in_interface: in_iface.to_string(),
                    out_interface: out_iface.to_string(),
                    comment: comment.to_string(),
                })
                .await?;
            Ok(())
        }
        "syslog_action" => {
            if item.action == "update" {
                // Delete existing and recreate
                if let Some(existing_id) = item.detail["existing_id"].as_str() {
                    client.delete("system/logging/action", existing_id).await?;
                }
            }
            client
                .create_logging_action(&CreateLoggingAction {
                    name: ACTION_NAME.to_string(),
                    target: "remote".to_string(),
                    remote: config.syslog_host.clone(),
                    remote_port: config.syslog_port,
                    src_address: Some(config.router_source_ip.clone()),
                    remote_log_format: Some("bsd-syslog".to_string()),
                    remote_protocol: None,
                })
                .await?;
            Ok(())
        }
        "syslog_rule" => {
            client
                .create_logging_rule(&CreateLoggingRule {
                    topics: "firewall".to_string(),
                    action: ACTION_NAME.to_string(),
                    prefix: None,
                })
                .await?;
            Ok(())
        }
        "firewall_log" => {
            let chain = item.detail["chain"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing chain in detail"))?;

            // Find the first existing rule in this chain to place before
            let filter_rules = client.firewall_filter_rules().await?;
            let place_before = filter_rules
                .iter()
                .find(|r| r.chain == chain)
                .map(|r| r.id.clone());

            client
                .create_filter_rule(&CreateFilterRule {
                    chain: chain.to_string(),
                    action: "log".to_string(),
                    connection_state: Some("new".to_string()),
                    in_interface_list: None,
                    log: Some("true".to_string()),
                    log_prefix: Some(LOG_PREFIX.to_string()),
                    comment: Some(FW_COMMENT.to_string()),
                    place_before,
                })
                .await?;
            Ok(())
        }
        other => Err(anyhow::anyhow!("unknown provision category: {other}")),
    }
}
