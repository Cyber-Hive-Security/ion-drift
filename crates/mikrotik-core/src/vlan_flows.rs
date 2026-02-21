use serde::Serialize;
use tracing::{debug, info};

use crate::MikrotikClient;
use crate::error::MikrotikError;
use crate::resources::firewall::CreateMangleRule;

/// A single inter-VLAN traffic flow (source → target with byte counter).
#[derive(Debug, Clone, Serialize)]
pub struct VlanFlow {
    pub source: String,
    pub target: String,
    pub bytes: u64,
}

/// Manages mangle passthrough rules used to count inter-VLAN traffic flows.
pub struct VlanFlowManager;

impl VlanFlowManager {
    const COMMENT_PREFIX: &'static str = "ion-drift-flow:";

    /// Ensure mangle passthrough rules exist for every VLAN pair.
    ///
    /// Creates rules in the `forward` chain with action `passthrough`.
    /// These rules have zero impact on routing — they just count bytes and pass through.
    ///
    /// Returns the number of new rules created.
    pub async fn setup_flow_counters(client: &MikrotikClient) -> Result<usize, MikrotikError> {
        // 1. Get all VLAN interface names
        let vlans = client.vlan_interfaces().await?;
        let vlan_names: Vec<String> = vlans.iter().map(|v| v.name.clone()).collect();
        debug!(count = vlan_names.len(), "found VLAN interfaces");

        if vlan_names.len() < 2 {
            info!("fewer than 2 VLAN interfaces, skipping flow counter setup");
            return Ok(0);
        }

        // 2. Fetch existing mangle rules and find our ion-drift ones
        let existing = client.firewall_mangle_rules().await?;
        let existing_comments: Vec<&str> = existing
            .iter()
            .filter_map(|r| r.comment.as_deref())
            .filter(|c| c.starts_with(Self::COMMENT_PREFIX))
            .collect();

        // 3. Create missing rules for each (src, dst) pair
        let mut created = 0usize;
        for src in &vlan_names {
            for dst in &vlan_names {
                if src == dst {
                    continue;
                }

                let comment = format!("{}{src}>{dst}", Self::COMMENT_PREFIX);
                if existing_comments.contains(&comment.as_str()) {
                    continue;
                }

                debug!(src, dst, "creating flow counter rule");
                client
                    .create_mangle_rule(&CreateMangleRule {
                        chain: "forward".into(),
                        action: "passthrough".into(),
                        in_interface: src.clone(),
                        out_interface: dst.clone(),
                        comment,
                    })
                    .await?;
                created += 1;
            }
        }

        let already_existed = (vlan_names.len() * (vlan_names.len() - 1)) - created;
        info!(
            created,
            already_existed,
            "VLAN flow counter setup complete"
        );

        Ok(created)
    }

    /// Query current flow data from ion-drift mangle rules.
    ///
    /// Returns flows that have accumulated at least 1 byte.
    pub async fn get_flows(client: &MikrotikClient) -> Result<Vec<VlanFlow>, MikrotikError> {
        let rules = client.firewall_mangle_rules().await?;

        let flows: Vec<VlanFlow> = rules
            .iter()
            .filter_map(|rule| {
                let comment = rule.comment.as_deref()?;
                let suffix = comment.strip_prefix(Self::COMMENT_PREFIX)?;
                let (src, dst) = suffix.split_once('>')?;

                let bytes = rule.bytes.unwrap_or(0);
                if bytes == 0 {
                    return None;
                }

                Some(VlanFlow {
                    source: src.to_string(),
                    target: dst.to_string(),
                    bytes,
                })
            })
            .collect();

        debug!(count = flows.len(), "retrieved VLAN flows with traffic");
        Ok(flows)
    }
}
