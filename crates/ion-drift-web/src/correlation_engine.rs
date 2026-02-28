use std::sync::Arc;
use std::time::Duration;

use mikrotik_core::SwitchStore;
use tokio::sync::RwLock;

use crate::device_manager::DeviceManager;
use crate::oui::OuiDb;

/// Spawn the correlation engine that runs every 60s to:
/// 1. Classify port roles (access/trunk/uplink/unused)
/// 2. Build unified network identities from MAC/neighbor/OUI data
pub fn spawn_correlation_engine(
    switch_store: Arc<SwitchStore>,
    oui_db: Arc<OuiDb>,
    device_manager: Arc<RwLock<DeviceManager>>,
) {
    tokio::spawn(async move {
        // 90-second startup delay — let switch pollers collect initial data
        tokio::time::sleep(Duration::from_secs(90)).await;
        tracing::info!("correlation engine starting (60s interval)");

        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;

        loop {
            interval.tick().await;

            if let Err(e) = run_correlation(&switch_store, &oui_db, &device_manager).await {
                tracing::warn!("correlation engine error: {e}");
            }
        }
    });
}

async fn run_correlation(
    store: &SwitchStore,
    oui_db: &OuiDb,
    device_manager: &Arc<RwLock<DeviceManager>>,
) -> anyhow::Result<()> {
    // ── 1. Port role classification ───────────────────────────────
    let dm_read = device_manager.read().await;
    let switches = dm_read.get_switches();
    let device_ids: Vec<String> = switches.iter().map(|d| d.record.id.clone()).collect();
    drop(dm_read);

    for device_id in &device_ids {
        let mac_entries = store.get_mac_table(Some(device_id)).await?;
        let vlan_entries = store.get_vlan_membership(device_id).await?;

        // Count MACs per port
        let mut mac_counts: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        for entry in &mac_entries {
            *mac_counts.entry(entry.port_name.clone()).or_default() += 1;
        }

        // Count VLANs per port
        let mut vlan_counts: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        for entry in &vlan_entries {
            *vlan_counts.entry(entry.port_name.clone()).or_default() += 1;
        }

        // Check LLDP neighbors per port
        let neighbors = store.get_neighbors(Some(device_id)).await?;
        let mut has_neighbor: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for nb in &neighbors {
            has_neighbor.insert(nb.interface.clone());
        }

        // Collect all known port names
        let mut all_ports: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        all_ports.extend(mac_counts.keys().cloned());
        all_ports.extend(vlan_counts.keys().cloned());

        for port_name in &all_ports {
            let mac_count = mac_counts.get(port_name).copied().unwrap_or(0);
            let vlan_count = vlan_counts.get(port_name).copied().unwrap_or(0);
            let has_lldp = has_neighbor.contains(port_name);

            let role = classify_port_role(mac_count, vlan_count, has_lldp);

            if let Err(e) = store
                .set_port_role(device_id, port_name, &role, vlan_count, mac_count, has_lldp)
                .await
            {
                tracing::warn!(device = %device_id, port = %port_name, "port role: {e}");
            }
        }
    }

    // ── 2. Unified identity assembly ──────────────────────────────
    let all_macs = store.get_mac_table(None).await?;
    let all_neighbors = store.get_neighbors(None).await?;

    // Build a map: MAC → best known info
    let mut identity_map: std::collections::HashMap<String, IdentityBuilder> =
        std::collections::HashMap::new();

    // From MAC table
    for entry in &all_macs {
        let builder = identity_map
            .entry(entry.mac_address.clone())
            .or_insert_with(|| IdentityBuilder::default());
        builder.switch_device_id = Some(entry.device_id.clone());
        builder.switch_port = Some(entry.port_name.clone());
        if entry.vlan_id.is_some() {
            builder.vlan_id = entry.vlan_id;
        }
    }

    // From neighbor discovery
    for nb in &all_neighbors {
        let mac = match &nb.mac_address {
            Some(m) if !m.is_empty() => m.clone(),
            _ => continue,
        };
        let builder = identity_map
            .entry(mac)
            .or_insert_with(|| IdentityBuilder::default());

        if let Some(ref addr) = nb.address {
            builder.best_ip = Some(addr.clone());
        }
        if let Some(ref identity) = nb.identity {
            builder.hostname = Some(identity.clone());
            builder.remote_identity = Some(identity.clone());
        }
        if let Some(ref platform) = nb.platform {
            builder.remote_platform = Some(platform.clone());
        }
        builder.discovery_protocol = Some("LLDP/MNDP".to_string());
    }

    // Enrich with OUI manufacturer
    for (mac, builder) in &mut identity_map {
        if let Some(manufacturer) = oui_db.lookup(mac) {
            builder.manufacturer = Some(manufacturer.to_string());
        }
    }

    // Write all identities
    let mut upserted = 0u32;
    for (mac, builder) in &identity_map {
        // Compute a simple confidence score based on how many fields we have
        let confidence = builder.confidence_score();

        if let Err(e) = store
            .upsert_network_identity(
                mac,
                builder.best_ip.as_deref(),
                builder.hostname.as_deref(),
                builder.manufacturer.as_deref(),
                builder.switch_device_id.as_deref(),
                builder.switch_port.as_deref(),
                builder.vlan_id,
                builder.discovery_protocol.as_deref(),
                builder.remote_identity.as_deref(),
                builder.remote_platform.as_deref(),
                confidence,
            )
            .await
        {
            tracing::warn!(mac = %mac, "identity upsert: {e}");
        } else {
            upserted += 1;
        }
    }

    if upserted > 0 {
        tracing::debug!(
            identities = upserted,
            switches = device_ids.len(),
            "correlation cycle complete"
        );
    }

    Ok(())
}

/// Classify a port's role based on MAC count, VLAN count, and LLDP neighbor presence.
fn classify_port_role(mac_count: u32, vlan_count: u32, has_lldp: bool) -> String {
    if vlan_count > 1 {
        "trunk".to_string()
    } else if has_lldp {
        "uplink".to_string()
    } else if mac_count > 10 {
        "uplink".to_string()
    } else if mac_count == 0 {
        "unused".to_string()
    } else {
        "access".to_string()
    }
}

/// Intermediate struct for building a network identity from multiple sources.
#[derive(Default)]
struct IdentityBuilder {
    best_ip: Option<String>,
    hostname: Option<String>,
    manufacturer: Option<String>,
    switch_device_id: Option<String>,
    switch_port: Option<String>,
    vlan_id: Option<u32>,
    discovery_protocol: Option<String>,
    remote_identity: Option<String>,
    remote_platform: Option<String>,
}

impl IdentityBuilder {
    /// Compute a confidence score (0.0 to 1.0) based on available data.
    fn confidence_score(&self) -> f64 {
        let mut score = 0.0;
        if self.best_ip.is_some() { score += 0.2; }
        if self.hostname.is_some() { score += 0.2; }
        if self.manufacturer.is_some() { score += 0.15; }
        if self.switch_port.is_some() { score += 0.15; }
        if self.discovery_protocol.is_some() { score += 0.15; }
        if self.vlan_id.is_some() { score += 0.15; }
        score
    }
}
