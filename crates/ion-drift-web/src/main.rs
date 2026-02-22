mod auth;
mod config;
mod geo;
mod live_traffic;
mod log_parser;
mod middleware;
mod oui;
mod routes;
mod state;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use tracing_subscriber::EnvFilter;

use crate::config::ServerConfig;
use crate::live_traffic::{LiveTrafficBuffer, TrafficSample};
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
    let config = ServerConfig::load(&config_file)?;
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

    // Build HTTP client with Smallstep CA cert (shared for OIDC + router)
    let http_client = auth::build_oidc_http_client(config.oidc.ca_cert_path.as_deref())?;

    // Discover OIDC provider
    tracing::info!("discovering OIDC provider at {}", config.oidc.issuer_url);
    let oidc_client = auth::discover_oidc(&config, &http_client).await?;
    tracing::info!("OIDC provider discovered successfully");

    // Set up data directory for SQLite databases
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("ion-drift");
    std::fs::create_dir_all(&data_dir)?;

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

    // Live traffic buffer (300 entries = 5 min at 1 sample per second, but we poll every 10s so ~50 min)
    let live_traffic = Arc::new(LiveTrafficBuffer::new(300));

    // Session store
    let sessions = auth::SessionStore::new(config.session.max_age_seconds);

    // Shared speedtest coordination
    let speedtest_running = Arc::new(AtomicBool::new(false));
    let speedtest_last_completed = Arc::new(AtomicI64::new(0));

    // Load MAC OUI database (bundled)
    let oui_db = oui::OuiDb::load();

    // Load GeoIP database (optional)
    let geo_db = geo::GeoDb::load(config.data.geoip_db_path.as_deref());

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
        geo_db,
        network_map_cache: Arc::new(tokio::sync::RwLock::new(None)),
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
        app_state.geo_db.clone(),
        app_state.oui_db.clone(),
    );
    spawn_speedtest_runner(
        speedtest_store.clone(),
        speedtest_running.clone(),
        speedtest_last_completed.clone(),
    );
    spawn_session_cleanup(sessions);

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
    geo_db: Arc<geo::GeoDb>,
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
                        .map(|e| log_parser::parse_log_entry(e, &geo_db, &oui_db))
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
