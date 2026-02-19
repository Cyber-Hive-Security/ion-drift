mod auth;
mod config;
mod middleware;
mod routes;
mod state;

use std::sync::Arc;
use std::time::Duration;

use tracing_subscriber::EnvFilter;

use crate::config::ServerConfig;
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

    // Session store
    let sessions = auth::SessionStore::new(config.session.max_age_seconds);

    // Build AppState
    let app_state = AppState {
        mikrotik: mikrotik.clone(),
        oidc_client,
        http_client: http_client.clone(),
        sessions: sessions.clone(),
        traffic_tracker: traffic_tracker.clone(),
        speedtest_store: speedtest_store.clone(),
        config: config.clone(),
    };

    // Spawn background tasks
    spawn_traffic_poller(traffic_tracker.clone(), mikrotik.clone());
    spawn_speedtest_runner(speedtest_store.clone());
    spawn_session_cleanup(sessions);

    // Build router and start server
    let app = routes::router(app_state);
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

/// Poll WAN traffic counters every 15 minutes.
fn spawn_traffic_poller(
    tracker: Arc<mikrotik_core::TrafficTracker>,
    client: mikrotik_core::MikrotikClient,
) {
    tokio::spawn(async move {
        // Initial poll on startup
        match tracker.poll(&client).await {
            Ok(t) => tracing::info!(
                "traffic initial poll: rx={}, tx={}", t.rx_bytes, t.tx_bytes
            ),
            Err(e) => tracing::warn!("traffic initial poll failed: {e}"),
        }

        let mut interval = tokio::time::interval(Duration::from_secs(900));
        interval.tick().await; // skip immediate tick
        loop {
            interval.tick().await;
            match tracker.poll(&client).await {
                Ok(t) => tracing::debug!(
                    "traffic poll: rx={}, tx={}", t.rx_bytes, t.tx_bytes
                ),
                Err(e) => tracing::warn!("traffic poll failed: {e}"),
            }
        }
    });
}

/// Run speed tests every 7 hours.
fn spawn_speedtest_runner(store: Arc<mikrotik_core::SpeedTestStore>) {
    tokio::spawn(async move {
        // Build a separate HTTP client for speedtests (public CAs only)
        let http_client = reqwest::Client::new();

        // Wait 5 minutes before first speedtest (let server stabilize)
        tokio::time::sleep(Duration::from_secs(300)).await;

        loop {
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

            tokio::time::sleep(Duration::from_secs(7 * 3600)).await;
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
