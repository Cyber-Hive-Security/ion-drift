mod alerting;
mod anomaly_correlator;
mod auth;
mod behavior_engine;
mod bootstrap;
mod certwarden;
mod config;
mod connection_store;
mod correlation_engine;
pub mod demo;
mod device_manager;
mod dns;
mod geo;
mod investigation;
mod live_traffic;
mod log_parser;
mod middleware;
mod oui;
mod passive_discovery;
mod poller_registry;
mod provision;
mod routes;
mod secrets;
mod setup;
mod snapshots;
mod snmp_poller;
mod state;
mod switch_poller;
mod swos_poller;
mod syslog;
mod task_supervisor;
mod tasks;
pub mod topology;
mod topology_inference;

use std::sync::Arc;

use secrecy::ExposeSecret;
use tracing_subscriber::EnvFilter;

use crate::config::ServerConfig;
use crate::live_traffic::LiveTrafficBuffer;
use crate::secrets::{DecryptedSecrets, SecretsManager};
use crate::state::AppState;
use crate::task_supervisor::TaskSupervisor;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing (RUST_LOG env filter, default info)
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("info,tower_http=warn,hyper=warn,mikrotik_core::snmp_client=debug")
        }))
        .init();

    // OpenSSL 3.x: explicitly loading any provider disables auto-loading of the default
    // provider. We need legacy for DES-CBC (Netgear "smart" switches) and must also
    // explicitly load default to keep SHA1/AES/etc. available.
    // Both handles must be kept alive for the process lifetime.
    let _openssl_default = openssl::provider::Provider::load(None, "default")
        .map_err(|e| tracing::warn!("failed to load OpenSSL default provider: {e}"))
        .ok();
    let _openssl_legacy = openssl::provider::Provider::load(None, "legacy")
        .map_err(|e| {
            tracing::warn!("failed to load OpenSSL legacy provider (DES may not work): {e}")
        })
        .ok();

    // Parse CLI args.
    let args = parse_args();
    let config_path = args.config_path.clone();
    let config_file = ServerConfig::resolve_path(config_path.as_deref());

    tracing::info!("loading config from {}", config_file.display());
    let mut config = ServerConfig::load(&config_file)?;

    // Set up data directory for SQLite databases
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("ion-drift");
    std::fs::create_dir_all(&data_dir)?;

    // ── Secrets management (Keycloak mTLS bootstrap) ────────────
    let secrets_manager: Option<Arc<tokio::sync::RwLock<SecretsManager>>> = if let Some(resolved) =
        config.resolve_bootstrap()?
    {
        let db_path = data_dir.join("secrets.db");
        let ca_cert_path = config
            .oidc
            .as_ref()
            .and_then(|o| o.ca_cert_path.as_deref())
            .ok_or_else(|| anyhow::anyhow!("oidc.ca_cert_path required for mTLS bootstrap"))?;

        // Check if cert+key exist on disk
        let cert_exists = std::path::Path::new(&config.tls.client_cert).exists();
        let key_exists = std::path::Path::new(&config.tls.client_key).exists();

        if cert_exists && key_exists {
            // Normal startup: cert on disk → build mTLS → fetch KEK → decrypt secrets
            tracing::info!(
                "mTLS cert found at {}, fetching KEK from Keycloak",
                config.tls.client_cert
            );
            let mtls_client = bootstrap::build_mtls_client(&resolved, ca_cert_path)?;
            let result = bootstrap::fetch_or_generate_kek(
                &mtls_client,
                &resolved,
                &data_dir,
                &config.tls.client_key,
            )
            .await?;
            let sm = SecretsManager::new(&db_path, result.kek)?;

            let has_secrets = sm.has_secrets().await?;
            let has_env_vars =
                !config.router.password.is_empty() && config.oidc.as_ref().map_or(false, |o| !o.client_secret.is_empty());

            if has_secrets {
                // Decrypt from DB and inject into config
                tracing::info!("loading encrypted secrets from database");
                let decrypted = sm.load_all().await?.ok_or_else(|| {
                    anyhow::anyhow!("secrets DB exists but some secrets are missing")
                })?;
                config.router.username = decrypted.router_username;
                config.router.password = decrypted.router_password.expose_secret().to_string();
                if let Some(ref mut oidc) = config.oidc {
                    oidc.client_secret =
                        decrypted.oidc_client_secret.expose_secret().to_string();
                }
                config.session.session_secret =
                    decrypted.session_secret.expose_secret().to_string();
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
                    oidc_client_secret: secrecy::SecretString::from(
                        config.oidc.as_ref().map_or(String::new(), |o| o.client_secret.clone()),
                    ),
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
            tracing::warn!(
                "no mTLS cert found at {} — starting in setup mode",
                config.tls.client_cert
            );
            return run_setup_mode(&config, &data_dir).await;
        }
    } else if !config.has_oidc() {
        // Local auth mode — no OIDC configured
        let db_path = data_dir.join("secrets.db");
        match bootstrap::load_local_kek(&data_dir)? {
            Some(result) => {
                let sm = SecretsManager::new(&db_path, result.kek)?;
                if sm.has_local_users().await? {
                    tracing::info!("local auth mode: loading from cached KEK");
                    // Load session secret into config if available
                    if let Ok(Some(ss)) = sm.decrypt_secret(secrets::SECRET_SESSION_SECRET).await {
                        config.session.session_secret = ss.expose_secret().to_string();
                    }
                    // Load router credentials if available
                    if let Ok(Some(u)) = sm.decrypt_secret(secrets::SECRET_ROUTER_USERNAME).await {
                        config.router.username = u.expose_secret().to_string();
                    }
                    if let Ok(Some(p)) = sm.decrypt_secret(secrets::SECRET_ROUTER_PASSWORD).await {
                        config.router.password = p.expose_secret().to_string();
                    }
                    Some(Arc::new(tokio::sync::RwLock::new(sm)))
                } else {
                    tracing::info!("local auth mode: no users yet, entering setup");
                    return run_local_setup_mode(&config, &data_dir).await;
                }
            }
            None => {
                tracing::info!("local auth mode: no KEK cache, entering setup");
                return run_local_setup_mode(&config, &data_dir).await;
            }
        }
    } else {
        None
    };

    // Warn if session cookies will be sent over HTTP on a non-localhost bind
    if !config.session.secure
        && config.server.listen_addr != "127.0.0.1"
        && config.server.listen_addr != "localhost"
    {
        tracing::warn!(
            "Session cookie 'secure' flag is disabled on a non-localhost bind address. Cookies will be sent over HTTP."
        );
    }

    tracing::info!(
        listen = %config.server.listen_addr,
        port = config.server.listen_port,
        router_host = %config.router.host,
        router_port = config.router.port,
        router_tls = config.router.tls,
        wan_interface = %config.router.wan_interface,
        oidc_issuer = %config.oidc.as_ref().map_or("(disabled)", |o| o.issuer_url.as_str()),
        session_max_age = config.session.max_age_seconds,
        syslog_port = config.syslog.port,
        "resolved configuration"
    );

    if args.dump_config {
        println!("{}", config.masked_toml()?);
        return Ok(());
    }

    let config = Arc::new(config);
    let dns_resolver = dns::build_dns_resolver(config.router.dns_server.as_deref());

    // ── Device Manager + SwitchStore ─────────────────────────────
    let switch_store = Arc::new(
        ion_drift_storage::SwitchStore::new(&data_dir.join("switch.db"))
            .map_err(|e| anyhow::anyhow!("failed to init switch store: {e}"))?,
    );

    let device_manager = if let Some(ref sm) = secrets_manager {
        let sm_read = sm.read().await;
        let has_devices = sm_read.has_devices().await.unwrap_or(false);

        if has_devices {
            // Load devices from registry
            tracing::info!("loading devices from registry");
            let dm = device_manager::DeviceManager::load(
                &sm_read,
                config.router.ca_cert_path.as_deref(),
            )
            .await?;
            drop(sm_read);
            dm
        } else {
            // No devices in registry — migrate from config/env vars
            drop(sm_read);
            tracing::info!("no devices in registry, creating primary router entry from config");
            let dm = device_manager::DeviceManager::from_config(&config)?;

            // Persist the primary router to the devices table
            let sm_read = sm.read().await;
            let new_device = secrets::NewDevice {
                id: "rb4011".to_string(),
                name: "RB4011".to_string(),
                host: config.router.host.clone(),
                port: config.router.port,
                tls: config.router.tls,
                ca_cert_path: config.router.ca_cert_path.clone(),
                device_type: "router".to_string(),
                model: Some("RB4011iGS+".to_string()),
                is_primary: true,
                enabled: true,
                poll_interval_secs: 60,
            };
            // Get credentials from existing encrypted secrets
            let username = sm_read
                .decrypt_secret(secrets::SECRET_ROUTER_USERNAME)
                .await?
                .map(|s| s.expose_secret().to_string())
                .unwrap_or_else(|| config.router.username.clone());
            let password = sm_read
                .decrypt_secret(secrets::SECRET_ROUTER_PASSWORD)
                .await?
                .map(|s| s.expose_secret().to_string())
                .unwrap_or_default();

            if let Err(e) = sm_read.add_device(&new_device, &username, &password).await {
                tracing::warn!("failed to persist primary router to device registry: {e}");
            } else {
                tracing::info!("migrated primary router to device registry");
            }
            drop(sm_read);
            dm
        }
    } else {
        // Legacy mode (no secrets manager) — build from config
        device_manager::DeviceManager::from_config(&config)?
    };

    let device_manager = Arc::new(tokio::sync::RwLock::new(device_manager));

    // Get primary router client (backward compat — existing handlers use state.mikrotik)
    let mikrotik = {
        let dm = device_manager.read().await;
        dm.get_router_client()
            .ok_or_else(|| anyhow::anyhow!("no primary router found in device manager"))?
    };

    // Test connectivity
    tracing::info!(
        "connecting to router at {}:{}",
        config.router.host,
        config.router.port
    );
    let router_name = mikrotik.test_connection().await?;
    tracing::info!("connected to router: {router_name}");

    // Update device status to Online
    {
        let mut dm = device_manager.write().await;
        dm.set_status(
            "rb4011",
            device_manager::DeviceStatus::Online {
                identity: router_name.clone(),
            },
        );
    }

    tracing::info!("router provisioning available via Setup Wizard (Settings > Setup Wizard)");

    // Build HTTP client with Smallstep CA cert (shared for OIDC + router)
    let http_client = auth::build_oidc_http_client(config.oidc.as_ref().and_then(|o| o.ca_cert_path.as_deref()))?;

    // Discover OIDC provider (only if configured)
    let oidc_client = if config.has_oidc() {
        let oidc = config.oidc.as_ref().unwrap();
        tracing::info!("discovering OIDC provider at {}", oidc.issuer_url);
        let client = auth::discover_oidc(&config, &http_client).await?;
        tracing::info!("OIDC provider discovered successfully");
        Some(client)
    } else {
        tracing::info!("OIDC not configured — running without SSO");
        None
    };

    // Initialize traffic tracker
    let traffic_tracker = Arc::new(
        mikrotik_core::TrafficTracker::new(&data_dir.join("traffic.db"), "1-WAN")
            .map_err(|e| anyhow::anyhow!("failed to init traffic tracker: {e}"))?,
    );
    let metrics_store = Arc::new(
        ion_drift_storage::MetricsStore::new(&data_dir.join("metrics.db"))
            .map_err(|e| anyhow::anyhow!("failed to init metrics store: {e}"))?,
    );
    let behavior_store = Arc::new(
        ion_drift_storage::BehaviorStore::new(&data_dir.join("behavior.db"))
            .map_err(|e| anyhow::anyhow!("failed to init behavior store: {e}"))?,
    );

    // Live traffic buffer (300 entries = 5 min at 1 sample per second, but we poll every 10s so ~50 min)
    let live_traffic = Arc::new(LiveTrafficBuffer::new(300));

    // Session store
    let sessions = auth::SessionStore::new(
        config.session.max_age_seconds,
        &data_dir.join("sessions.db"),
        &config.session.session_secret,
    )?;

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
        geo::GeoCache::new(
            &data_dir.join("geo.db"),
            Some(&geoip_dir),
            config.server.warning_countries.clone(),
        )
        .map_err(|e| anyhow::anyhow!("failed to init geo cache: {e}"))?,
    );

    // Load persisted monitored regions from database (overrides TOML default if set)
    if let Ok(Some(json)) = switch_store.get_setting("monitored_regions").await {
        if let Ok(regions) = serde_json::from_str::<Vec<String>>(&json) {
            geo_cache.set_monitored_regions(regions);
        }
    }

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

    // Build VlanRegistry from database VLAN configs
    let vlan_registry = {
        let configs = switch_store.get_vlan_configs().await.unwrap_or_default();
        Arc::new(tokio::sync::RwLock::new(
            ion_drift_storage::behavior::VlanRegistry::from_configs(&configs),
        ))
    };

    // Create task supervisor
    let supervisor = TaskSupervisor::new();

    // Build AppState
    let app_state = AppState {
        mikrotik: mikrotik.clone(),
        oidc_client,
        http_client: http_client.clone(),
        sessions: sessions.clone(),
        traffic_tracker: traffic_tracker.clone(),
        metrics_store: metrics_store.clone(),
        live_traffic: live_traffic.clone(),
        config: config.clone(),
        oui_db,
        geo_cache: geo_cache.clone(),
        connection_store: connection_store.clone(),
        network_map_cache: Arc::new(tokio::sync::RwLock::new(None)),
        behavior_store: behavior_store.clone(),
        firewall_rules_cache: Arc::new(tokio::sync::RwLock::new((
            Vec::new(),
            std::time::Instant::now(),
        ))),
        secrets_manager: secrets_manager.clone(),
        device_manager: device_manager.clone(),
        switch_store: switch_store.clone(),
        topology_cache: Arc::new(tokio::sync::RwLock::new(None)),
        vlan_registry: vlan_registry.clone(),
        poller_registry: Arc::new(tokio::sync::RwLock::new(
            poller_registry::PollerRegistry::new(),
        )),
        task_supervisor: supervisor,
        login_limiter: auth::LoginRateLimiter::new(),
    };

    // Spawn all background tasks
    tasks::spawn_all(&app_state, dns_resolver);

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
        tracing::warn!(
            "SPA directory not found at {}, only API routes available",
            web_dist.display()
        );
    }

    // Log demo mode status
    if demo::is_demo_mode() {
        tracing::warn!("DEMO MODE ACTIVE — all API responses will have sensitive data sanitized");
    }

    // Build router and start server
    let app = routes::router(app_state, web_dist)?;
    let bind_addr = format!(
        "{}:{}",
        config.server.listen_addr, config.server.listen_port
    );
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("ion-drift web server listening on {bind_addr}");

    axum::serve(listener, app).await?;

    Ok(())
}

/// Run the setup-mode server when no cert/secrets are present.
async fn run_setup_mode(config: &ServerConfig, data_dir: &std::path::Path) -> anyhow::Result<()> {
    let db_path = data_dir.join("secrets.db");

    let setup_state = setup::SetupState {
        db_path,
        router_username: config.router.username.clone(),
        tls_config: config.tls.clone(),
        oidc_bootstrap: config.oidc.as_ref().and_then(|o| o.bootstrap.clone()),
        ca_cert_path: config.oidc.as_ref().and_then(|o| o.ca_cert_path.clone()).unwrap_or_default(),
        certwarden_base_url: config.certwarden.base_url.clone(),
        certwarden_cert_name: config.certwarden.cert_name.clone(),
    };

    let app = axum::Router::new()
        .route(
            "/setup",
            axum::routing::get(setup::setup_page).post(setup::setup_submit),
        )
        .route(
            "/health",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({ "status": "setup_required" }))
            }),
        )
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

/// Run the local-auth setup-mode server when no KEK cache or local users exist.
///
/// Presents a form to create the initial admin account, derives the KEK from the
/// password, caches it with a machine key, and exits for Docker/systemd restart.
async fn run_local_setup_mode(config: &ServerConfig, data_dir: &std::path::Path) -> anyhow::Result<()> {
    let state = setup::LocalSetupState {
        db_path: data_dir.join("secrets.db"),
    };

    let app = axum::Router::new()
        .route(
            "/setup",
            axum::routing::get(setup::local_setup_page).post(setup::local_setup_submit),
        )
        .route(
            "/health",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({ "status": "setup_required" }))
            }),
        )
        .fallback(|| async { axum::response::Redirect::temporary("/setup") })
        .with_state(state);

    // Setup mode binds to localhost only — prevents unauthenticated network access
    let bind_addr = format!("127.0.0.1:{}", config.server.listen_port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("ion-drift local setup server listening on {bind_addr} (localhost only)");
    tracing::info!("navigate to http://{bind_addr}/setup to create admin account");

    axum::serve(listener, app).await?;
    Ok(())
}

struct CliArgs {
    config_path: Option<String>,
    dump_config: bool,
}

/// Parse `--config <path>` and `--dump-config` from CLI args.
fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path = None;
    let mut dump_config = false;
    for i in 0..args.len() {
        if args[i] == "--config" {
            config_path = args.get(i + 1).cloned();
        }
        if args[i] == "--dump-config" {
            dump_config = true;
        }
    }
    CliArgs {
        config_path,
        dump_config,
    }
}
