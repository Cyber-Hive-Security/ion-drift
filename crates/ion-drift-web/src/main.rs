mod anomaly_correlator;
mod auth;
mod behavior_engine;
mod bootstrap;
mod certwarden;
mod config;
mod connection_store;
mod geo;
mod live_traffic;
mod log_parser;
mod middleware;
mod oui;
mod routes;
mod secrets;
mod setup;
mod snapshots;
mod state;
mod syslog;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use secrecy::ExposeSecret;
use tracing_subscriber::EnvFilter;

use crate::config::ServerConfig;
use crate::live_traffic::{LiveTrafficBuffer, TrafficSample};
use crate::secrets::{DecryptedSecrets, SecretsManager};
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing (RUST_LOG env filter, default info)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Parse CLI args (just --config for now)
    let config_path = parse_config_arg();
    let config_file = ServerConfig::resolve_path(config_path.as_deref());

    tracing::info!("loading config from {}", config_file.display());
    let mut config = ServerConfig::load(&config_file)?;

    // Set up data directory for SQLite databases
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("ion-drift");
    std::fs::create_dir_all(&data_dir)?;

    // ── Secrets management (Keycloak mTLS bootstrap) ────────────
    let secrets_manager: Option<Arc<tokio::sync::RwLock<SecretsManager>>> =
        if let Some(resolved) = config.resolve_bootstrap()? {
            let db_path = data_dir.join("secrets.db");
            let ca_cert_path = config.oidc.ca_cert_path.as_deref()
                .ok_or_else(|| anyhow::anyhow!("oidc.ca_cert_path required for mTLS bootstrap"))?;

            // Check if cert+key exist on disk
            let cert_exists = std::path::Path::new(&config.tls.client_cert).exists();
            let key_exists = std::path::Path::new(&config.tls.client_key).exists();

            if cert_exists && key_exists {
                // Normal startup: cert on disk → build mTLS → fetch KEK → decrypt secrets
                tracing::info!("mTLS cert found at {}, fetching KEK from Keycloak", config.tls.client_cert);
                let mtls_client = bootstrap::build_mtls_client(&resolved, ca_cert_path)?;
                let result = bootstrap::fetch_or_generate_kek(&mtls_client, &resolved, &data_dir, &config.tls.client_key).await?;
                let sm = SecretsManager::new(&db_path, result.kek)?;

                let has_secrets = sm.has_secrets().await?;
                let has_env_vars = !config.router.password.is_empty()
                    && !config.oidc.client_secret.is_empty();

                if has_secrets {
                    // Decrypt from DB and inject into config
                    tracing::info!("loading encrypted secrets from database");
                    let decrypted = sm
                        .load_all()
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("secrets DB exists but some secrets are missing"))?;
                    config.router.username = decrypted.router_username;
                    config.router.password = decrypted.router_password.expose_secret().to_string();
                    config.oidc.client_secret = decrypted.oidc_client_secret.expose_secret().to_string();
                    config.session.session_secret = decrypted.session_secret.expose_secret().to_string();
                } else if has_env_vars {
                    // Migrate env vars into encrypted DB
                    tracing::info!("migrating env var secrets to encrypted storage");
                    let session_secret = if config.session.session_secret.is_empty() {
                        let bytes: [u8; 32] = rand::random();
                        hex::encode(bytes)
                    } else {
                        config.session.session_secret.clone()
                    };
                    let decrypted = DecryptedSecrets {
                        router_username: config.router.username.clone(),
                        router_password: secrecy::SecretString::from(config.router.password.clone()),
                        oidc_client_secret: secrecy::SecretString::from(config.oidc.client_secret.clone()),
                        session_secret: secrecy::SecretString::from(session_secret.clone()),
                        certwarden_cert_api_key: None,
                        certwarden_key_api_key: None,
                        maxmind_account_id: None,
                        maxmind_license_key: None,
                    };
                    sm.store_all(&decrypted).await?;
                    config.session.session_secret = session_secret;
                    tracing::info!("secrets migrated to encrypted storage");
                } else {
                    // Cert on disk but no secrets — shouldn't happen normally,
                    // but fall through to setup mode
                    tracing::warn!("cert on disk but no secrets found — starting in setup mode");
                    return run_setup_mode(&config, &data_dir).await;
                }

                Some(Arc::new(tokio::sync::RwLock::new(sm)))
            } else {
                // No cert on disk — enter setup mode
                tracing::warn!("no mTLS cert found at {} — starting in setup mode", config.tls.client_cert);
                return run_setup_mode(&config, &data_dir).await;
            }
        } else {
            None
        };

    let config = Arc::new(config);

    // Build MikrotikClient and test connectivity
    tracing::info!("connecting to router at {}:{}", config.router.host, config.router.port);
    let mikrotik = mikrotik_core::MikrotikClient::new(config.mikrotik_config())?;
    let router_name = mikrotik.test_connection().await?;
    tracing::info!("connected to router: {router_name}");

    // Set up VLAN flow counter mangle rules (non-fatal on failure)
    tracing::info!("setting up VLAN flow counters...");
    match mikrotik_core::VlanFlowManager::setup_flow_counters(&mikrotik).await {
        Ok(n) => tracing::info!("VLAN flow counter setup complete ({n} new rules created)"),
        Err(e) => tracing::warn!("VLAN flow counter setup failed (dashboard flows unavailable): {e}"),
    }

    // Set up syslog forwarding from router to ion-drift (non-fatal on failure)
    tracing::info!("configuring router syslog forwarding...");
    match setup_router_syslog(&mikrotik).await {
        Ok(msg) => tracing::info!("syslog setup: {msg}"),
        Err(e) => tracing::warn!("syslog setup failed (syslog capture unavailable): {e}"),
    }

    // Build HTTP client with Smallstep CA cert (shared for OIDC + router)
    let http_client = auth::build_oidc_http_client(config.oidc.ca_cert_path.as_deref())?;

    // Discover OIDC provider
    tracing::info!("discovering OIDC provider at {}", config.oidc.issuer_url);
    let oidc_client = auth::discover_oidc(&config, &http_client).await?;
    tracing::info!("OIDC provider discovered successfully");

    // Initialize traffic tracker and speedtest store
    let traffic_tracker = Arc::new(
        mikrotik_core::TrafficTracker::new(&data_dir.join("traffic.db"), "1-WAN")
            .map_err(|e| anyhow::anyhow!("failed to init traffic tracker: {e}"))?,
    );
    let speedtest_store = Arc::new(
        mikrotik_core::SpeedTestStore::new(&data_dir.join("speedtest.db"))
            .map_err(|e| anyhow::anyhow!("failed to init speedtest store: {e}"))?,
    );
    let metrics_store = Arc::new(
        mikrotik_core::MetricsStore::new(&data_dir.join("metrics.db"))
            .map_err(|e| anyhow::anyhow!("failed to init metrics store: {e}"))?,
    );
    let behavior_store = Arc::new(
        mikrotik_core::BehaviorStore::new(&data_dir.join("behavior.db"))
            .map_err(|e| anyhow::anyhow!("failed to init behavior store: {e}"))?,
    );

    // Live traffic buffer (300 entries = 5 min at 1 sample per second, but we poll every 10s so ~50 min)
    let live_traffic = Arc::new(LiveTrafficBuffer::new(300));

    // Session store
    let sessions = auth::SessionStore::new(config.session.max_age_seconds);

    // Shared speedtest coordination
    let speedtest_running = Arc::new(AtomicBool::new(false));
    let speedtest_last_completed = Arc::new(AtomicI64::new(0));

    // Load MAC OUI database (bundled)
    let oui_db = oui::OuiDb::load();

    // Initialize connection history store (SQLite)
    let connection_store = std::sync::Arc::new(
        connection_store::ConnectionStore::new(&data_dir.join("connections.db"))
            .map_err(|e| anyhow::anyhow!("failed to init connection store: {e}"))?,
    );

    // Initialize IP geolocation cache (MaxMind primary, ip-api.com fallback)
    let geoip_dir = data_dir.join("geoip");
    std::fs::create_dir_all(&geoip_dir)?;
    let geo_cache = std::sync::Arc::new(
        geo::GeoCache::new(&data_dir.join("geo.db"), Some(&geoip_dir))
            .map_err(|e| anyhow::anyhow!("failed to init geo cache: {e}"))?,
    );

    // Auto-download MaxMind databases if credentials are available but files are missing
    if !geo_cache.has_maxmind() {
        if let Some(ref sm) = secrets_manager {
            let sm_read = sm.read().await;
            let account_id = sm_read
                .decrypt_secret(secrets::SECRET_MAXMIND_ACCOUNT_ID)
                .await
                .ok()
                .flatten();
            let license_key = sm_read
                .decrypt_secret(secrets::SECRET_MAXMIND_LICENSE_KEY)
                .await
                .ok()
                .flatten();
            drop(sm_read);

            if let (Some(account_id), Some(license_key)) = (account_id, license_key) {
                tracing::info!("MaxMind databases not loaded — attempting auto-download");
                match geo::download_maxmind_databases(
                    &geoip_dir,
                    account_id.expose_secret(),
                    license_key.expose_secret(),
                )
                .await
                {
                    Ok(downloaded) => {
                        if !downloaded.is_empty() {
                            tracing::info!("MaxMind downloaded: {}", downloaded.join(", "));
                            geo_cache.hot_swap_maxmind(&geoip_dir);
                        }
                    }
                    Err(e) => tracing::warn!("MaxMind auto-download failed: {e}"),
                }
            }
        }
    }

    // Build AppState
    let app_state = AppState {
        mikrotik: mikrotik.clone(),
        oidc_client,
        http_client: http_client.clone(),
        sessions: sessions.clone(),
        traffic_tracker: traffic_tracker.clone(),
        speedtest_store: speedtest_store.clone(),
        metrics_store: metrics_store.clone(),
        live_traffic: live_traffic.clone(),
        config: config.clone(),
        speedtest_running: speedtest_running.clone(),
        speedtest_last_completed: speedtest_last_completed.clone(),
        oui_db,
        geo_cache: geo_cache.clone(),
        connection_store: connection_store.clone(),
        network_map_cache: Arc::new(tokio::sync::RwLock::new(None)),
        behavior_store: behavior_store.clone(),
        firewall_rules_cache: Arc::new(tokio::sync::RwLock::new((Vec::new(), std::time::Instant::now()))),
        secrets_manager: secrets_manager.clone(),
    };

    // Spawn background tasks
    spawn_traffic_poller(traffic_tracker.clone(), live_traffic.clone(), mikrotik.clone());
    spawn_metrics_poller(metrics_store.clone(), mikrotik.clone());
    spawn_drops_poller(metrics_store.clone(), mikrotik.clone());
    spawn_connection_metrics_poller(metrics_store.clone(), mikrotik.clone());
    spawn_vlan_metrics_poller(metrics_store.clone(), mikrotik.clone());
    spawn_log_aggregation(
        metrics_store.clone(),
        mikrotik.clone(),
        app_state.geo_cache.clone(),
        app_state.oui_db.clone(),
    );
    // Automatic speedtest disabled — use on-demand /api/speedtest/run instead
    // spawn_speedtest_runner(
    //     speedtest_store.clone(),
    //     speedtest_running.clone(),
    //     speedtest_last_completed.clone(),
    // );
    spawn_session_cleanup(sessions);
    spawn_behavior_collector(
        behavior_store.clone(),
        mikrotik.clone(),
        app_state.oui_db.clone(),
        app_state.geo_cache.clone(),
        app_state.firewall_rules_cache.clone(),
    );
    spawn_behavior_maintenance(behavior_store.clone(), connection_store.clone());
    spawn_behavior_auto_classifier(behavior_store.clone());
    anomaly_correlator::spawn_anomaly_correlator(connection_store.clone(), behavior_store);

    // Spawn connection history persistence + pruning
    spawn_connection_persister(
        connection_store.clone(),
        mikrotik.clone(),
        geo_cache.clone(),
    );
    spawn_connection_pruner(connection_store.clone());

    // Spawn weekly snapshot generator
    snapshots::spawn_snapshot_generator(connection_store.clone());

    // Spawn syslog listener (UDP 5514 by default) — only accepts packets from configured router
    syslog::spawn_syslog_listener(5514, connection_store, geo_cache, config.router.host.clone());

    // Spawn cert rotation background task if CertWarden is configured
    if let Some(ref sm) = secrets_manager {
        if let Some(cw_config) = config.certwarden.resolve() {
            if let Some(ca_path) = config.oidc.ca_cert_path.as_deref() {
                spawn_cert_rotation(
                    sm.clone(),
                    cw_config,
                    config.tls.clone(),
                    ca_path.to_string(),
                );
            }
        }
    }

    // Resolve web/dist path relative to the config file's parent (project root)
    let web_dist = config_file
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("web/dist");
    if web_dist.is_dir() {
        tracing::info!("serving SPA from {}", web_dist.display());
    } else {
        tracing::warn!("SPA directory not found at {}, only API routes available", web_dist.display());
    }

    // Build router and start server
    let app = routes::router(app_state, web_dist);
    let bind_addr = format!("{}:{}", config.server.listen_addr, config.server.listen_port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("ion-drift web server listening on {bind_addr}");

    axum::serve(listener, app).await?;

    Ok(())
}

/// Run the setup-mode server when no cert/secrets are present.
async fn run_setup_mode(
    config: &ServerConfig,
    data_dir: &std::path::Path,
) -> anyhow::Result<()> {
    let db_path = data_dir.join("secrets.db");

    let setup_state = setup::SetupState {
        db_path,
        router_username: config.router.username.clone(),
        tls_config: config.tls.clone(),
        oidc_bootstrap: config.oidc.bootstrap.clone(),
        ca_cert_path: config.oidc.ca_cert_path.clone().unwrap_or_default(),
        certwarden_base_url: config.certwarden.base_url.clone(),
        certwarden_cert_name: config.certwarden.cert_name.clone(),
    };

    let app = axum::Router::new()
        .route("/setup", axum::routing::get(setup::setup_page).post(setup::setup_submit))
        .route("/health", axum::routing::get(|| async {
            axum::Json(serde_json::json!({ "status": "setup_required" }))
        }))
        .fallback(|| async { axum::response::Redirect::temporary("/setup") })
        .with_state(setup_state);

    // Setup mode binds to localhost only — prevents unauthenticated network access
    let bind_addr = format!("127.0.0.1:{}", config.server.listen_port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("ion-drift setup server listening on {bind_addr} (localhost only)");
    tracing::info!("navigate to http://{bind_addr}/setup to configure secrets");

    axum::serve(listener, app).await?;
    Ok(())
}

/// Parse `--config <path>` from CLI args.
fn parse_config_arg() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    for i in 0..args.len() {
        if args[i] == "--config" {
            return args.get(i + 1).cloned();
        }
    }
    None
}

/// Background task: check cert expiry and renew from CertWarden when within threshold.
fn spawn_cert_rotation(
    sm: Arc<tokio::sync::RwLock<SecretsManager>>,
    cw_config: config::ResolvedCertWarden,
    tls_config: config::TlsSection,
    ca_cert_path: String,
) {
    let interval_hours = cw_config.check_interval_hours.max(1) as u64;
    let threshold_secs = (cw_config.renewal_threshold_days as i64) * 86400;

    tokio::spawn(async move {
        // 5-minute initial delay before first check
        tokio::time::sleep(Duration::from_secs(300)).await;
        tracing::info!(
            "cert rotation task started: checking every {}h, renewing within {}d of expiry",
            interval_hours,
            cw_config.renewal_threshold_days
        );

        loop {
            // Check cert expiry
            match certwarden::check_cert_status(&tls_config.client_cert) {
                Ok(status) => {
                    tracing::debug!(
                        cn = %status.subject_cn,
                        days_until_expiry = status.seconds_until_expiry / 86400,
                        "cert expiry check"
                    );

                    if status.seconds_until_expiry <= threshold_secs {
                        tracing::info!(
                            days_remaining = status.seconds_until_expiry / 86400,
                            "cert within renewal threshold, attempting renewal"
                        );

                        // Decrypt CertWarden API keys
                        let sm_read = sm.read().await;
                        let cert_key = sm_read.decrypt_secret(secrets::SECRET_CW_CERT_API_KEY).await;
                        let key_key = sm_read.decrypt_secret(secrets::SECRET_CW_KEY_API_KEY).await;
                        drop(sm_read);

                        match (cert_key, key_key) {
                            (Ok(Some(cert_api_key)), Ok(Some(key_api_key))) => {
                                match certwarden::CertWardenClient::new(&cw_config, &ca_cert_path) {
                                    Ok(cw_client) => {
                                        match cw_client.fetch_cert_and_key(
                                            cert_api_key.expose_secret(),
                                            key_api_key.expose_secret(),
                                        ).await {
                                            Ok((cert_pem, key_pem)) => {
                                                match certwarden::write_cert_and_key(
                                                    &tls_config.client_cert,
                                                    &tls_config.client_key,
                                                    &cert_pem,
                                                    &key_pem,
                                                ) {
                                                    Ok(()) => tracing::info!("cert renewed successfully"),
                                                    Err(e) => tracing::warn!("cert write failed: {e}"),
                                                }
                                            }
                                            Err(e) => tracing::warn!("cert fetch from CertWarden failed: {e}"),
                                        }
                                    }
                                    Err(e) => tracing::warn!("failed to create CertWarden client: {e}"),
                                }
                            }
                            _ => tracing::warn!("CertWarden API keys not found in secrets DB, skipping renewal"),
                        }
                    }
                }
                Err(e) => tracing::warn!("cert status check failed: {e}"),
            }

            tokio::time::sleep(Duration::from_secs(interval_hours * 3600)).await;
        }
    });
}

/// Poll WAN traffic counters every 10 seconds for live rates,
/// and every 15 minutes for lifetime totals (SQLite).
fn spawn_traffic_poller(
    tracker: Arc<mikrotik_core::TrafficTracker>,
    live_buf: Arc<LiveTrafficBuffer>,
    client: mikrotik_core::MikrotikClient,
) {
    tokio::spawn(async move {
        // Initial poll for lifetime totals
        match tracker.poll(&client).await {
            Ok(t) => tracing::info!(
                "traffic initial poll: rx={}, tx={}", t.rx_bytes, t.tx_bytes
            ),
            Err(e) => tracing::warn!("traffic initial poll failed: {e}"),
        }

        let mut prev_rx: Option<u64> = None;
        let mut prev_tx: Option<u64> = None;
        let mut prev_time: Option<std::time::Instant> = None;
        let mut tick_count: u64 = 0;

        let mut interval = tokio::time::interval(Duration::from_secs(10));
        interval.tick().await; // skip immediate tick
        loop {
            interval.tick().await;
            tick_count += 1;

            // Fetch current interface counters
            let interfaces = match client.interfaces().await {
                Ok(i) => i,
                Err(e) => {
                    tracing::warn!("live traffic poll failed: {e}");
                    continue;
                }
            };

            let wan = interfaces.iter().find(|i| i.name == "1-WAN");
            if let Some(wan) = wan {
                let current_rx = wan.rx_byte.unwrap_or(0);
                let current_tx = wan.tx_byte.unwrap_or(0);
                let now = std::time::Instant::now();

                // Compute per-second rates if we have a previous sample
                if let (Some(prx), Some(ptx), Some(pt)) = (prev_rx, prev_tx, prev_time) {
                    let elapsed = now.duration_since(pt).as_secs_f64();
                    if elapsed > 0.0 && current_rx >= prx && current_tx >= ptx {
                        let rx_bps = ((current_rx - prx) as f64 / elapsed) * 8.0;
                        let tx_bps = ((current_tx - ptx) as f64 / elapsed) * 8.0;
                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64;
                        live_buf
                            .push(TrafficSample {
                                timestamp,
                                rx_bps,
                                tx_bps,
                            })
                            .await;
                    }
                }

                prev_rx = Some(current_rx);
                prev_tx = Some(current_tx);
                prev_time = Some(now);
            }

            // Poll lifetime totals every 90 ticks (~15 minutes at 10s interval)
            if tick_count % 90 == 0 {
                match tracker.poll(&client).await {
                    Ok(t) => tracing::debug!(
                        "traffic poll: rx={}, tx={}", t.rx_bytes, t.tx_bytes
                    ),
                    Err(e) => tracing::warn!("traffic poll failed: {e}"),
                }
            }
        }
    });
}

/// Poll system resources every 60 seconds, store CPU/memory metrics.
/// Prune data older than 7 days every hour.
fn spawn_metrics_poller(
    store: Arc<mikrotik_core::MetricsStore>,
    client: mikrotik_core::MikrotikClient,
) {
    tokio::spawn(async move {
        let mut tick_count: u64 = 0;
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            tick_count += 1;

            match client.system_resources().await {
                Ok(res) => {
                    let memory_used = res.total_memory - res.free_memory;
                    if let Err(e) = store
                        .record(res.cpu_load, memory_used, res.total_memory)
                        .await
                    {
                        tracing::warn!("metrics record failed: {e}");
                    }
                }
                Err(e) => tracing::warn!("metrics poll failed: {e}"),
            }

            // Cleanup all tables every 60 ticks (every hour)
            if tick_count % 60 == 0 {
                if let Err(e) = store.cleanup(7 * 86400).await {
                    tracing::warn!("metrics cleanup failed: {e}");
                }
            }
        }
    });
}

/// Poll firewall drop counters every 60 seconds, store totals in SQLite.
fn spawn_drops_poller(
    store: Arc<mikrotik_core::MetricsStore>,
    client: mikrotik_core::MikrotikClient,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;

            let rules = match client.firewall_filter_rules().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("drops poller: failed to fetch rules: {e}");
                    continue;
                }
            };

            let (total_packets, total_bytes) = rules
                .iter()
                .filter(|r| r.action == "drop")
                .fold((0u64, 0u64), |(p, b), r| {
                    (p + r.packets.unwrap_or(0), b + r.bytes.unwrap_or(0))
                });

            if let Err(e) = store.record_drops(total_packets, total_bytes).await {
                tracing::warn!("drops poller: record failed: {e}");
            }
        }
    });
}

/// Poll connection tracking summary every 60 seconds, store in SQLite.
fn spawn_connection_metrics_poller(
    store: Arc<mikrotik_core::MetricsStore>,
    client: mikrotik_core::MikrotikClient,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;

            let connections = match client.firewall_connections(".id,protocol").await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("connection poller: failed to fetch connections: {e}");
                    continue;
                }
            };

            let mut tcp = 0u32;
            let mut udp = 0u32;
            let mut other = 0u32;
            for c in &connections {
                match c.protocol.as_deref() {
                    Some("6") | Some("tcp") => tcp += 1,
                    Some("17") | Some("udp") => udp += 1,
                    _ => other += 1,
                }
            }
            let total = connections.len() as u32;

            if let Err(e) = store.record_connections(total, tcp, udp, other).await {
                tracing::warn!("connection poller: record failed: {e}");
            }
        }
    });
}

/// Poll VLAN throughput every 60 seconds, store in SQLite.
fn spawn_vlan_metrics_poller(
    store: Arc<mikrotik_core::MetricsStore>,
    client: mikrotik_core::MikrotikClient,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;

            let vlans = match client.vlan_interfaces().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("VLAN poller: failed to fetch VLANs: {e}");
                    continue;
                }
            };

            // Monitor each VLAN concurrently
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
                        entries.push((name, rx, tx));
                    }
                    Ok((name, Err(e))) => {
                        tracing::debug!(vlan = %name, error = %e, "VLAN poller: monitor failed");
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "VLAN poller: task panicked");
                    }
                }
            }

            if !entries.is_empty() {
                if let Err(e) = store.record_vlan_metrics(&entries).await {
                    tracing::warn!("VLAN poller: record failed: {e}");
                }
            }
        }
    });
}

/// Aggregate log statistics every hour, store roll-ups in SQLite.
fn spawn_log_aggregation(
    store: Arc<mikrotik_core::MetricsStore>,
    client: mikrotik_core::MikrotikClient,
    geo_cache: Arc<geo::GeoCache>,
    oui_db: Arc<oui::OuiDb>,
) {
    tokio::spawn(async move {
        // Wait 2 minutes before first aggregation (let server stabilize)
        tokio::time::sleep(Duration::from_secs(120)).await;

        loop {
            let period_end = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let period_start = period_end - 3600;

            match client.log_entries().await {
                Ok(raw_entries) => {
                    let entries: Vec<_> = raw_entries
                        .iter()
                        .map(|e| log_parser::parse_log_entry(e, &geo_cache, &oui_db))
                        .collect();

                    let total_entries = entries.len() as u32;
                    let mut drop_count = 0u32;
                    let mut accept_count = 0u32;
                    let mut src_counts: HashMap<String, u32> = HashMap::new();
                    let mut port_counts: HashMap<u32, u32> = HashMap::new();
                    let mut iface_counts: HashMap<String, u32> = HashMap::new();

                    for entry in &entries {
                        if let Some(ref parsed) = entry.parsed {
                            match parsed.action.as_deref() {
                                Some("drop") => {
                                    drop_count += 1;
                                    if let Some(ref ip) = parsed.src_ip {
                                        *src_counts.entry(ip.clone()).or_default() += 1;
                                    }
                                    if let Some(port) = parsed.dst_port {
                                        *port_counts.entry(port as u32).or_default() += 1;
                                    }
                                    if let Some(ref iface) = parsed.in_interface {
                                        *iface_counts.entry(iface.clone()).or_default() += 1;
                                    }
                                }
                                Some("accept") => accept_count += 1,
                                _ => {}
                            }
                        }
                    }

                    let top_src = src_counts
                        .iter()
                        .max_by_key(|(_, c)| *c)
                        .map(|(ip, c)| (ip.clone(), *c));
                    let top_port = port_counts
                        .iter()
                        .max_by_key(|(_, c)| *c)
                        .map(|(p, c)| (*p, *c));

                    let drops_by_interface =
                        serde_json::to_string(&iface_counts).unwrap_or_else(|_| "{}".into());

                    if let Err(e) = store
                        .record_log_aggregate(
                            period_start,
                            period_end,
                            total_entries,
                            drop_count,
                            accept_count,
                            top_src.as_ref().map(|(ip, _)| ip.as_str()),
                            top_src.as_ref().map(|(_, c)| *c).unwrap_or(0),
                            top_port.as_ref().map(|(p, _)| *p),
                            top_port.as_ref().map(|(_, c)| *c).unwrap_or(0),
                            &drops_by_interface,
                        )
                        .await
                    {
                        tracing::warn!("log aggregation: record failed: {e}");
                    } else {
                        tracing::info!(
                            "log aggregation: recorded {} entries, {} drops, {} accepts",
                            total_entries,
                            drop_count,
                            accept_count,
                        );
                    }
                }
                Err(e) => tracing::warn!("log aggregation: failed to fetch logs: {e}"),
            }

            // Sleep for 1 hour
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
}

/// Run speed tests once per week, coordinating with on-demand tests.
fn spawn_speedtest_runner(
    store: Arc<mikrotik_core::SpeedTestStore>,
    running: Arc<AtomicBool>,
    last_completed: Arc<AtomicI64>,
) {
    tokio::spawn(async move {
        // Build a separate HTTP client for speedtests (public CAs only)
        let http_client = reqwest::Client::new();

        // Wait 5 minutes before first speedtest (let server stabilize)
        tokio::time::sleep(Duration::from_secs(300)).await;

        loop {
            // Try to claim the running flag; skip if an on-demand test is in progress
            if running
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                tracing::info!("starting scheduled speed test");
                let result = mikrotik_core::speedtest::run_speedtest(&http_client).await;
                tracing::info!(
                    "speedtest complete: {:.1}/{:.1} Mbps (down/up)",
                    result.median_download_mbps,
                    result.median_upload_mbps,
                );
                if let Err(e) = store.save(&result).await {
                    tracing::error!("failed to save speedtest result: {e}");
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                last_completed.store(now, Ordering::Release);
                running.store(false, Ordering::Release);
            } else {
                tracing::info!("scheduled speedtest skipped: on-demand test in progress");
            }

            tokio::time::sleep(Duration::from_secs(7 * 24 * 3600)).await;
        }
    });
}

/// Clean up expired sessions every 10 minutes.
fn spawn_session_cleanup(sessions: auth::SessionStore) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(600));
        loop {
            interval.tick().await;
            sessions.cleanup();
            tracing::debug!("session cleanup complete");
        }
    });
}

/// Collect device observations, detect anomalies, and detect blocked attempts every 60s.
/// 3-minute startup delay to let the server stabilize.
fn spawn_behavior_collector(
    store: Arc<mikrotik_core::BehaviorStore>,
    client: mikrotik_core::MikrotikClient,
    oui_db: Arc<oui::OuiDb>,
    geo_cache: Arc<geo::GeoCache>,
    firewall_cache: Arc<tokio::sync::RwLock<(Vec<mikrotik_core::resources::firewall::FilterRule>, std::time::Instant)>>,
) {
    tokio::spawn(async move {
        // Wait 3 minutes before first collection
        tokio::time::sleep(Duration::from_secs(180)).await;
        tracing::info!("behavior collector starting");

        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;

            // Refresh firewall rules cache
            behavior_engine::refresh_firewall_cache(&client, &firewall_cache).await;

            // Collect observations
            match behavior_engine::collect_observations(&client, &store, &oui_db).await {
                Ok(count) => {
                    tracing::debug!("behavior: collected {count} observations");
                }
                Err(e) => {
                    tracing::warn!("behavior: observation collection failed: {e}");
                    continue;
                }
            }

            // Detect anomalies
            match behavior_engine::detect_anomalies(&store).await {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!("behavior: detected {count} anomalies");
                    }
                }
                Err(e) => tracing::warn!("behavior: anomaly detection failed: {e}"),
            }

            // Detect blocked attempts
            match behavior_engine::detect_blocked_attempts(&client, &store, &oui_db, &geo_cache).await
            {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!("behavior: detected {count} blocked attempts");
                    }
                }
                Err(e) => tracing::warn!("behavior: blocked attempt detection failed: {e}"),
            }
        }
    });
}

/// Recompute all device baselines nightly (3 AM) and prune old observations.
fn spawn_behavior_maintenance(
    store: Arc<mikrotik_core::BehaviorStore>,
    connection_store: Arc<connection_store::ConnectionStore>,
) {
    tokio::spawn(async move {
        loop {
            // Sleep until roughly 3 AM — simplified: sleep 24 hours
            tokio::time::sleep(Duration::from_secs(24 * 3600)).await;

            tracing::info!("behavior maintenance: recomputing baselines");
            match store.recompute_all_baselines(7 * 86400).await {
                Ok(count) => tracing::info!("behavior: recomputed baselines for {count} devices"),
                Err(e) => tracing::warn!("behavior: baseline recompute failed: {e}"),
            }

            match store.prune_observations(30 * 86400).await {
                Ok(count) => tracing::info!("behavior: pruned {count} old observations"),
                Err(e) => tracing::warn!("behavior: observation prune failed: {e}"),
            }

            // Compute port flow baselines for Sankey anomaly detection
            tracing::info!("computing port flow baselines");
            match connection_store.compute_port_flow_baselines() {
                Ok(count) => tracing::info!("port flow baselines: computed {count} baselines"),
                Err(e) => tracing::warn!("port flow baseline computation failed: {e}"),
            }
        }
    });
}

/// Auto-resolve stale anomalies every hour based on per-VLAN timeout rules.
fn spawn_behavior_auto_classifier(store: Arc<mikrotik_core::BehaviorStore>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match store.auto_resolve_stale().await {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!("behavior: auto-resolved {count} stale anomalies");
                    }
                }
                Err(e) => tracing::warn!("behavior: auto-resolve failed: {e}"),
            }
        }
    });
}

/// Persist active connections to history every 30 seconds (same cadence as the connections page poll).
fn spawn_connection_persister(
    store: Arc<connection_store::ConnectionStore>,
    client: mikrotik_core::MikrotikClient,
    geo_cache: Arc<geo::GeoCache>,
) {
    tokio::spawn(async move {
        // Wait 1 minute before starting (let server stabilize)
        tokio::time::sleep(Duration::from_secs(60)).await;
        tracing::info!("connection history persister starting");

        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;

            let connections = match client.firewall_connections_full().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("connection persister: failed to fetch connections: {e}");
                    continue;
                }
            };

            let mut inserted = 0usize;
            let mut updated = 0usize;
            let mut active_ids: Vec<String> = Vec::with_capacity(connections.len());

            for c in &connections {
                let conntrack_id = c.id.clone();
                active_ids.push(conntrack_id.clone());

                let protocol = c
                    .protocol
                    .as_deref()
                    .map(|p| match p {
                        "6" | "tcp" => "tcp",
                        "17" | "udp" => "udp",
                        "1" | "icmp" => "icmp",
                        _ => "other",
                    })
                    .unwrap_or("other")
                    .to_string();

                let src_ip = c.src_address.as_deref().unwrap_or("");
                let dst_ip = c.dst_address.as_deref().unwrap_or("");
                let dst_port = c
                    .dst_port
                    .as_deref()
                    .and_then(|p| p.parse::<i64>().ok());

                let poll_conn = connection_store::PollConnection {
                    conntrack_id,
                    protocol,
                    src_ip: src_ip.to_string(),
                    dst_ip: dst_ip.to_string(),
                    dst_port,
                    src_mac: None,
                    tcp_state: c.tcp_state.clone(),
                    bytes_tx: c.orig_bytes.unwrap_or(0) as i64,
                    bytes_rx: c.repl_bytes.unwrap_or(0) as i64,
                };

                match store.upsert_from_poll(&poll_conn, &geo_cache) {
                    Ok(true) => inserted += 1,
                    Ok(false) => updated += 1,
                    Err(e) => tracing::debug!("connection persist error: {e}"),
                }
            }

            // Close connections that disappeared from the poll
            match store.close_stale(&active_ids, 60) {
                Ok(closed) => {
                    if closed > 0 || inserted > 0 {
                        tracing::debug!(
                            "connections: +{inserted} new, ~{updated} updated, -{closed} closed"
                        );
                    }
                }
                Err(e) => tracing::warn!("connection close_stale error: {e}"),
            }
        }
    });
}


/// Prune old connection history nightly.
fn spawn_connection_pruner(store: Arc<connection_store::ConnectionStore>) {
    tokio::spawn(async move {
        // Wait 3 hours before first prune (avoid startup load)
        tokio::time::sleep(Duration::from_secs(3 * 3600)).await;

        loop {
            match store.prune(30) {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!("connection history: pruned {count} old rows");
                    }
                }
                Err(e) => tracing::warn!("connection history prune failed: {e}"),
            }

            // Sleep 24 hours
            tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
        }
    });
}

/// Configure the router to send firewall syslog to ion-drift.
///
/// Creates (idempotently):
/// 1. A remote logging action "ion-drift" → 10.20.25.17:5514
/// 2. A logging rule routing topic "firewall" to that action
/// 3. Firewall log rules for new connections on input + forward chains
async fn setup_router_syslog(
    client: &mikrotik_core::MikrotikClient,
) -> anyhow::Result<String> {
    const SYSLOG_TARGET: &str = "10.20.25.17";
    const SYSLOG_PORT: u16 = 5514;
    const ACTION_NAME: &str = "ion-drift";
    const LOG_PREFIX: &str = "ION";
    const COMMENT: &str = "ion-drift syslog capture";

    let mut actions_taken: Vec<&str> = Vec::new();

    // ── Step 1: Ensure remote logging action exists ──────────────
    let actions = client.system_logging_actions().await?;
    let has_action = actions.iter().any(|a| a.name == ACTION_NAME);

    if !has_action {
        tracing::info!("creating remote logging action '{ACTION_NAME}' → {SYSLOG_TARGET}:{SYSLOG_PORT}");
        client
            .create_logging_action(&mikrotik_core::CreateLoggingAction {
                name: ACTION_NAME.to_string(),
                target: "remote".to_string(),
                remote: SYSLOG_TARGET.to_string(),
                remote_port: SYSLOG_PORT,
                src_address: Some("10.20.25.1".to_string()),
                bsd_syslog: Some("yes".to_string()),
            })
            .await?;
        actions_taken.push("created logging action");
    }

    // ── Step 2: Ensure logging rule routes firewall topic ────────
    let rules = client.system_logging_rules().await?;
    let has_rule = rules
        .iter()
        .any(|r| r.action == ACTION_NAME && r.topics.contains("firewall"));

    if !has_rule {
        tracing::info!("creating logging rule: topic 'firewall' → action '{ACTION_NAME}'");
        client
            .create_logging_rule(&mikrotik_core::CreateLoggingRule {
                topics: "firewall".to_string(),
                action: ACTION_NAME.to_string(),
                prefix: None,
            })
            .await?;
        actions_taken.push("created firewall logging rule");
    }

    // ── Step 3: Ensure firewall rules log new connections ────────
    let filter_rules = client.firewall_filter_rules().await?;

    // Check if log rules with our prefix already exist
    let has_ion_log = filter_rules.iter().any(|r| {
        r.action == "log"
            && r.log_prefix.as_deref() == Some(LOG_PREFIX)
    });

    if !has_ion_log {
        // Find the first rule in each chain to use as place-before target
        let first_forward = filter_rules
            .iter()
            .find(|r| r.chain == "forward")
            .map(|r| r.id.clone());
        let first_input = filter_rules
            .iter()
            .find(|r| r.chain == "input")
            .map(|r| r.id.clone());

        // Log new forward connections (internal↔external and inter-VLAN)
        tracing::info!("creating firewall log rule for 'forward' chain (new connections)");
        client
            .create_filter_rule(&mikrotik_core::CreateFilterRule {
                chain: "forward".to_string(),
                action: "log".to_string(),
                connection_state: Some("new".to_string()),
                in_interface_list: None,
                log: Some("true".to_string()),
                log_prefix: Some(LOG_PREFIX.to_string()),
                comment: Some(COMMENT.to_string()),
                place_before: first_forward,
            })
            .await?;

        // Log new input connections (traffic directed at the router itself)
        tracing::info!("creating firewall log rule for 'input' chain (new connections)");
        client
            .create_filter_rule(&mikrotik_core::CreateFilterRule {
                chain: "input".to_string(),
                action: "log".to_string(),
                connection_state: Some("new".to_string()),
                in_interface_list: None,
                log: Some("true".to_string()),
                log_prefix: Some(LOG_PREFIX.to_string()),
                comment: Some(COMMENT.to_string()),
                place_before: first_input,
            })
            .await?;

        actions_taken.push("created firewall log rules (forward + input)");
    }

    if actions_taken.is_empty() {
        Ok("all syslog config already present".to_string())
    } else {
        Ok(actions_taken.join(", "))
    }
}
