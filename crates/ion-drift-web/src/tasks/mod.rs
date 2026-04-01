mod behavior;
mod cert;
mod connections;
mod metrics;
mod policy_deviation_detector;
mod policy_sync;
pub(crate) mod port_baselines;
mod traffic;

use crate::dns::DnsResolver;
use crate::state::AppState;

/// Spawn all background tasks using shared application state.
pub fn spawn_all(state: &AppState, dns_resolver: std::sync::Arc<dyn DnsResolver>) {
    // Traffic polling
    traffic::spawn_traffic_poller(
        state.traffic_tracker.clone(),
        state.live_traffic.clone(),
        state.router_queue.clone(),
        state.config.polling.traffic_interval_secs,
        state.mikrotik.clone(),
        state.config.router.wan_interface.clone(),
    );
    traffic::spawn_vlan_metrics_poller(
        state.metrics_store.clone(),
        state.router_queue.clone(),
        state.config.polling.metrics_interval_secs,
        state.mikrotik.clone(),
    );

    // System metrics
    metrics::spawn_metrics_poller(
        state.metrics_store.clone(),
        state.router_queue.clone(),
        state.config.polling.metrics_interval_secs,
    );
    metrics::spawn_drops_poller(
        state.metrics_store.clone(),
        state.router_queue.clone(),
        state.config.polling.metrics_interval_secs,
    );
    metrics::spawn_connection_metrics_poller(
        state.metrics_store.clone(),
        state.router_queue.clone(),
        state.config.polling.metrics_interval_secs,
    );
    metrics::spawn_log_aggregation(
        state.metrics_store.clone(),
        state.router_queue.clone(),
        state.geo_cache.clone(),
        state.oui_db.clone(),
    );

    // Session cleanup + login rate limiter cleanup
    spawn_session_cleanup(state.sessions.clone(), state.login_limiter.clone());

    // Behavior analysis + automated investigation
    behavior::spawn_behavior_collector(
        state.behavior_store.clone(),
        state.router_queue.clone(),
        state.oui_db.clone(),
        state.geo_cache.clone(),
        state.connection_store.clone(),
        state.firewall_rules_cache.clone(),
        state.vlan_registry.clone(),
        state.config.polling.behavior_interval_secs,
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
        state.config.polling.correlation_interval_secs,
    );

    // Policy synchronization
    policy_sync::spawn_policy_sync(
        state.router_queue.clone(),
        state.behavior_store.clone(),
        state.vlan_registry.clone(),
        state.config.polling.policy_sync_interval_secs,
        state.config.router.wan_interface.clone(),
    );

    // Connection history
    connections::spawn_connection_persister(
        state.connection_store.clone(),
        state.router_queue.clone(),
        state.geo_cache.clone(),
        state.vlan_registry.clone(),
        state.config.polling.connection_interval_secs,
    );
    connections::spawn_connection_pruner(state.connection_store.clone());
    crate::snapshots::spawn_snapshot_generator(
        &state.task_supervisor,
        state.connection_store.clone(),
    );

    // Syslog listener
    crate::syslog::spawn_syslog_listener(
        &state.task_supervisor,
        state.config.syslog.port,
        state.config.syslog.bind_address.clone(),
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
    crate::switch_poller::spawn_device_health_check(
        &state.task_supervisor,
        state.device_manager.clone(),
    );
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
        state.router_queue.clone(),
        dns_resolver,
        state.infrastructure_snapshot.clone(),
        state.config.polling.correlation_interval_secs,
    );
    crate::topology::spawn_topology_updater(
        &state.task_supervisor,
        state.switch_store.clone(),
        state.device_manager.clone(),
        state.behavior_store.clone(),
        state.topology_cache.clone(),
        state.infrastructure_snapshot.clone(),
        state.config.router.wan_interface.clone(),
    );
    crate::passive_discovery::spawn_passive_discovery(
        &state.task_supervisor,
        state.switch_store.clone(),
        state.router_queue.clone(),
        state.config.polling.topology_interval_secs,
    );

    // Policy deviation detection (DNS + NTP)
    policy_deviation_detector::spawn_policy_deviation_detector(
        state.behavior_store.clone(),
        state.connection_store.clone(),
        state.vlan_registry.clone(),
        state.attack_techniques.clone(),
        state.device_manager.clone(),
    );

    // Port rate baselines
    port_baselines::spawn_port_baselines(
        state.switch_store.clone(),
        state.device_manager.clone(),
    );

    // Alert engine
    crate::alerting::spawn_alert_engine(
        &state.task_supervisor,
        state.clone(),
        state.config.polling.metrics_interval_secs,
    );

    // Page view stats pruning (daily, retain 90 days)
    spawn_stats_pruner(state.stats_store.clone());

    // Cert rotation (only if CertWarden is configured)
    if let Some(ref sm) = state.secrets_manager {
        if let Some(cw_config) = state.config.certwarden.resolve() {
            if let Some(ca_path) = state.config.oidc.as_ref().and_then(|o| o.ca_cert_path.as_deref()) {
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

/// Prune old page view stats daily (retain 90 days).
fn spawn_stats_pruner(stats_store: std::sync::Arc<crate::stats_store::StatsStore>) {
    tokio::spawn(async move {
        // Wait 1 hour before first prune
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        loop {
            stats_store.prune_old_views(90).await;
            // Run once per day
            tokio::time::sleep(std::time::Duration::from_secs(86400)).await;
        }
    });
}

/// Clean up expired sessions every 10 minutes.
fn spawn_session_cleanup(
    sessions: crate::auth::SessionStore,
    login_limiter: crate::auth::LoginRateLimiter,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            sessions.cleanup();
            sessions.flush_dirty();
            login_limiter.cleanup();
            tracing::debug!("session + rate limiter cleanup complete");
        }
    });
}
