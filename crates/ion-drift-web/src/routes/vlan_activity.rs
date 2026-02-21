use axum::extract::State;
use axum::response::{Json, Response};
use serde::Serialize;

use crate::middleware::RequireAuth;
use crate::state::AppState;
use super::api_error;

#[derive(Serialize)]
pub struct VlanActivityEntry {
    pub name: String,
    pub rx_bps: u64,
    pub tx_bps: u64,
}

/// GET /api/traffic/vlan-activity
pub async fn vlan_activity(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<VlanActivityEntry>>, Response> {
    let vlans = state
        .mikrotik
        .vlan_interfaces()
        .await
        .map_err(api_error)?;

    // Spawn concurrent monitor_traffic calls for each VLAN
    let client = state.mikrotik.clone();
    let mut handles = Vec::with_capacity(vlans.len());

    for vlan in &vlans {
        let c = client.clone();
        let name = vlan.name.clone();
        handles.push(tokio::spawn(async move {
            let result = c.monitor_traffic(&name).await;
            (name, result)
        }));
    }

    let results = futures::future::join_all(handles).await;

    let mut entries = Vec::new();
    for result in results {
        match result {
            Ok((name, Ok(samples))) => {
                let rx = samples.first().and_then(|s| s.rx_bits_per_second).unwrap_or(0);
                let tx = samples.first().and_then(|s| s.tx_bits_per_second).unwrap_or(0);
                entries.push(VlanActivityEntry {
                    name,
                    rx_bps: rx,
                    tx_bps: tx,
                });
            }
            Ok((name, Err(e))) => {
                tracing::warn!(vlan = %name, error = %e, "failed to monitor VLAN traffic");
            }
            Err(e) => {
                tracing::warn!(error = %e, "VLAN monitor task panicked");
            }
        }
    }

    Ok(Json(entries))
}
