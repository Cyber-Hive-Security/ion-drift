mod behavior;
mod cert;
mod connections;
mod metrics;
mod traffic;

use crate::state::AppState;
use crate::dns::DnsResolver;

/// Spawn all background tasks using shared application state.
pub fn spawn_all(state: &AppState, dns_resolver: std::sync::Arc<dyn DnsResolver>) {
    // Traffic polling
    traffic::spawn_traffic_poller(
        state.traffic_tracker.clone(),
        state.live_traffic.clone(),
        state.mikrotik.clone(),
    );
    traffic::spawn_vlan_metrics_poller(
        state.metrics_store.clone(),
        state.mikrotik.clone(),
    );

    // System metrics
    metrics::spawn_metrics_poller(
        state.metrics_store.clone(),
        state.mikrotik.clone(),
    );
    metrics::spawn_drops_poller(
        state.metrics_store.clone(),
        state.mikrotik.clone(),
    );
    metrics::spawn_connection_metrics_poller(
        state.metrics_store.clone(),
        state.mikrotik.clone(),
    );
    metrics::spawn_log_aggregation(
        state.metrics_store.clone(),
        state.mikrotik.clone(),
        state.geo_cache.clone(),
        state.oui_db.clone(),
    );

    // Session cleanup
    spawn_session_cleanup(state.sessions.clone());

    // Behavior analysis
    behavior::spawn_behavior_collector(
        state.behavior_store.clone(),
        state.mikrotik.clone(),
        state.oui_db.clone(),
        state.geo_cache.clone(),
        state.firewall_rules_cache.clone(),
        state.vlan_registry.clone(),
    );
    behavior::spawn_behavior_maintenance(
        state.behavior_store.clone(),
        state.connection_store.clone(),
        state.switch_store.clone(),
        state.vlan_registry.clone(),
    );
    behavior::spawn_behavior_auto_classifier(
        state.behavior_store.clone(),
        state.vlan_registry.clone(),
    );
    crate::anomaly_correlator::spawn_anomaly_correlator(
        &state.task_supervisor,
        state.connection_store.clone(),
        state.behavior_store.clone(),
        state.vlan_registry.clone(),
    );

    // Connection history
    connections::spawn_connection_persister(
        state.connection_store.clone(),
        state.mikrotik.clone(),
        state.geo_cache.clone(),
        state.vlan_registry.clone(),
    );
    connections::spawn_connection_pruner(state.connection_store.clone());
    crate::snapshots::spawn_snapshot_generator(&state.task_supervisor, state.connection_store.clone());

    // Syslog listener
    crate::syslog::spawn_syslog_listener(
        &state.task_supervisor,
        5514,
        state.connection_store.clone(),
        state.geo_cache.clone(),
        state.config.router.host.clone(),
        state.vlan_registry.clone(),
    );

    // Multi-device pollers
    crate::switch_poller::spawn_switch_pollers(
        &state.task_supervisor,
        state.device_manager.clone(),
        state.switch_store.clone(),
        state.poller_registry.clone(),
    );
    crate::switch_poller::spawn_neighbor_poller(
        &state.task_supervisor,
        state.device_manager.clone(),
        state.switch_store.clone(),
    );
    crate::switch_poller::spawn_device_health_check(&state.task_supervisor, state.device_manager.clone());
    crate::swos_poller::spawn_swos_pollers(
        state.device_manager.clone(),
        state.switch_store.clone(),
        state.poller_registry.clone(),
    );
    crate::snmp_poller::spawn_snmp_pollers(
        state.device_manager.clone(),
        state.switch_store.clone(),
        state.poller_registry.clone(),
    );

    // Correlation and topology
    crate::correlation_engine::spawn_correlation_engine(
        &state.task_supervisor,
        state.switch_store.clone(),
        state.oui_db.clone(),
        state.device_manager.clone(),
        state.mikrotik.clone(),
        dns_resolver,
    );
    crate::topology::spawn_topology_updater(
        &state.task_supervisor,
        state.switch_store.clone(),
        state.device_manager.clone(),
        state.topology_cache.clone(),
    );
    crate::passive_discovery::spawn_passive_discovery(
        &state.task_supervisor,
        state.switch_store.clone(),
        state.mikrotik.clone(),
    );

    // Cert rotation (only if CertWarden is configured)
    if let Some(ref sm) = state.secrets_manager {
        if let Some(cw_config) = state.config.certwarden.resolve() {
            if let Some(ca_path) = state.config.oidc.ca_cert_path.as_deref() {
                cert::spawn_cert_rotation(
                    sm.clone(),
                    cw_config,
                    state.config.tls.clone(),
                    ca_path.to_string(),
                );
            }
        }
    }
}

/// Clean up expired sessions every 10 minutes.
fn spawn_session_cleanup(sessions: crate::auth::SessionStore) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
        loop {
            interval.tick().await;
            sessions.cleanup();
            tracing::debug!("session cleanup complete");
        }
    });
}
