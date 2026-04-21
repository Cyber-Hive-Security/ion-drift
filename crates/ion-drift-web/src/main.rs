mod alerting;
mod anomaly_correlator;
mod attack_techniques;
mod auth;
mod behavior_engine;
mod bootstrap;
mod certwarden;
mod config;
mod connection_store;
mod correlation_engine;
pub mod demo;
mod device_manager;
mod device_queue_registry;
mod device_resolution;
mod dns;
mod geo;
mod identity_utils;
mod infrastructure_snapshot;
mod investigation;
mod license;
mod live_traffic;
mod log_parser;
mod middleware;
mod module_adapters;
mod modules;
mod modules_registry;
mod oui;
mod passive_discovery;
mod poller_registry;
mod provision;
mod router_queue;
mod routes;
mod secrets;
mod setup;
mod snapshots;
mod snmp_poller;
mod state;
mod stats_store;
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
    // Record process start time for uptime reporting
    crate::routes::stats::init_start_time();

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
                    let bytes: [u8; 32] = {
                        use rand::rngs::OsRng;
                        use rand::TryRngCore;
                        let mut b = [0u8; 32];
                        OsRng.try_fill_bytes(&mut b)
                            .map_err(|e| anyhow::anyhow!("OS RNG failed: {e}"))?;
                        b
                    };
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
                    // Load session secret — fatal on decrypt error (KEK mismatch means
                    // all secrets are unreadable, continuing would use an empty HMAC key).
                    match sm.decrypt_secret(secrets::SECRET_SESSION_SECRET).await {
                        Ok(Some(ss)) => config.session.session_secret = ss.expose_secret().to_string(),
                        Ok(None) => {
                            // Not yet stored (e.g., upgrade from older version). Generate ephemeral
                            // secret so sessions work, but warn that they won't survive restarts.
                            let bytes: [u8; 32] = {
                        use rand::rngs::OsRng;
                        use rand::TryRngCore;
                        let mut b = [0u8; 32];
                        OsRng.try_fill_bytes(&mut b)
                            .map_err(|e| anyhow::anyhow!("OS RNG failed: {e}"))?;
                        b
                    };
                            config.session.session_secret = hex::encode(bytes);
                            tracing::warn!("session secret not found in secrets.db — generated ephemeral secret (sessions will not survive restarts)");
                        }
                        Err(e) => {
                            anyhow::bail!(
                                "failed to decrypt session secret: {e} — this usually means the encryption key (KEK) has changed. \
                                 Was the data directory recreated without machine.key? Ion Drift cannot start safely."
                            );
                        }
                    }
                    // Load router credentials from DB if available.
                    // Distinguish Err (KEK mismatch / corruption) from Ok(None) (not yet stored).
                    // Only Ok(None) should allow env var migration; Err is fatal.
                    match sm.decrypt_secret(secrets::SECRET_ROUTER_USERNAME).await {
                        Ok(Some(u)) => config.router.username = u.expose_secret().to_string(),
                        Ok(None) => {}
                        Err(e) => {
                            anyhow::bail!(
                                "failed to decrypt router username: {e} — KEK mismatch or data corruption. Ion Drift cannot start safely."
                            );
                        }
                    }
                    let db_has_password = match sm.decrypt_secret(secrets::SECRET_ROUTER_PASSWORD).await {
                        Ok(Some(p)) => {
                            config.router.password = p.expose_secret().to_string();
                            true
                        }
                        Ok(None) => {
                            tracing::warn!("router password not found in secrets.db — router connections will fail until configured");
                            false
                        }
                        Err(e) => {
                            anyhow::bail!(
                                "failed to decrypt router password: {e} — KEK mismatch or data corruption. Ion Drift cannot start safely."
                            );
                        }
                    };

                    // Migrate env var credentials into encrypted DB if not already stored.
                    // This handles the case where DRIFT_ROUTER_PASSWORD is set in compose
                    // but the setup wizard only created the admin account (no router creds).
                    // Only runs when db_has_password is false (Ok(None)), never on Err (which bails above).
                    if !db_has_password && !config.router.password.is_empty() {
                        tracing::info!("migrating router credentials from env var to encrypted storage");
                        if let Err(e) = sm.encrypt_secret(secrets::SECRET_ROUTER_USERNAME, &config.router.username).await {
                            tracing::warn!("failed to migrate router username: {e}");
                        }
                        if let Err(e) = sm.encrypt_secret(secrets::SECRET_ROUTER_PASSWORD, &config.router.password).await {
                            tracing::warn!("failed to migrate router password: {e}");
                        }
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
        // OIDC without mTLS bootstrap — derive KEK from the OIDC client secret
        let db_path = data_dir.join("secrets.db");
        let oidc_secret = config.oidc.as_ref()
            .map(|o| o.client_secret.clone())
            .unwrap_or_default();

        match bootstrap::load_local_kek(&data_dir)? {
            Some(result) => {
                let sm = SecretsManager::new(&db_path, result.kek)?;
                tracing::info!("OIDC mode (no mTLS): loading from cached KEK");
                // Load secrets — decrypt errors are fatal (KEK mismatch means all secrets
                // are unreadable; continuing would use empty/default values unsafely).
                match sm.decrypt_secret(secrets::SECRET_SESSION_SECRET).await {
                    Ok(Some(ss)) => config.session.session_secret = ss.expose_secret().to_string(),
                    Ok(None) => {
                        let bytes: [u8; 32] = {
                        use rand::rngs::OsRng;
                        use rand::TryRngCore;
                        let mut b = [0u8; 32];
                        OsRng.try_fill_bytes(&mut b)
                            .map_err(|e| anyhow::anyhow!("OS RNG failed: {e}"))?;
                        b
                    };
                        config.session.session_secret = hex::encode(bytes);
                        tracing::warn!("session secret not found in secrets.db — generated ephemeral secret (sessions will not survive restarts)");
                    }
                    Err(e) => {
                        anyhow::bail!(
                            "failed to decrypt session secret: {e} — KEK mismatch or data corruption. Ion Drift cannot start safely."
                        );
                    }
                }
                match sm.decrypt_secret(secrets::SECRET_ROUTER_USERNAME).await {
                    Ok(Some(u)) => config.router.username = u.expose_secret().to_string(),
                    Ok(None) => {}
                    Err(e) => {
                        anyhow::bail!(
                            "failed to decrypt router username: {e} — KEK mismatch or data corruption. Ion Drift cannot start safely."
                        );
                    }
                }
                match sm.decrypt_secret(secrets::SECRET_ROUTER_PASSWORD).await {
                    Ok(Some(p)) => config.router.password = p.expose_secret().to_string(),
                    Ok(None) => tracing::warn!("router password not found in secrets.db — router connections will fail until configured"),
                    Err(e) => {
                        anyhow::bail!(
                            "failed to decrypt router password: {e} — KEK mismatch or data corruption. Ion Drift cannot start safely."
                        );
                    }
                }
                match sm.decrypt_secret(secrets::SECRET_OIDC_CLIENT_SECRET).await {
                    Ok(Some(cs)) => {
                        if let Some(ref mut oidc) = config.oidc {
                            oidc.client_secret = cs.expose_secret().to_string();
                        }
                    }
                    Ok(None) => tracing::warn!("OIDC client secret not found in secrets.db — OIDC authentication will fail"),
                    Err(e) => {
                        anyhow::bail!(
                            "failed to decrypt OIDC client secret: {e} — KEK mismatch or data corruption. Ion Drift cannot start safely."
                        );
                    }
                }
                Some(Arc::new(tokio::sync::RwLock::new(sm)))
            }
            None => {
                // First run: derive KEK from OIDC client secret, cache it, migrate secrets
                if oidc_secret.is_empty() {
                    anyhow::bail!(
                        "OIDC client secret required for initial KEK derivation — set DRIFT_OIDC_SECRET env var on first run"
                    );
                }
                tracing::info!("OIDC mode (no mTLS): deriving KEK from client secret");
                let kek_result = bootstrap::derive_kek_from_password(&oidc_secret, &data_dir)?;
                bootstrap::cache_kek_locally(&kek_result.kek, &data_dir)?;

                let sm = SecretsManager::new(&db_path, kek_result.kek)?;

                // Generate session secret
                let session_secret = if config.session.session_secret.is_empty() {
                    let bytes: [u8; 32] = {
                        use rand::rngs::OsRng;
                        use rand::TryRngCore;
                        let mut b = [0u8; 32];
                        OsRng.try_fill_bytes(&mut b)
                            .map_err(|e| anyhow::anyhow!("OS RNG failed: {e}"))?;
                        b
                    };
                    hex::encode(bytes)
                } else {
                    config.session.session_secret.clone()
                };

                // Migrate secrets from env vars / config into encrypted storage
                let decrypted = DecryptedSecrets {
                    router_username: config.router.username.clone(),
                    router_password: secrecy::SecretString::from(config.router.password.clone()),
                    oidc_client_secret: secrecy::SecretString::from(oidc_secret),
                    session_secret: secrecy::SecretString::from(session_secret.clone()),
                    certwarden_cert_api_key: None,
                    certwarden_key_api_key: None,
                    maxmind_account_id: None,
                    maxmind_license_key: None,
                };
                sm.store_all(&decrypted).await?;
                config.session.session_secret = session_secret;
                tracing::info!("OIDC mode (no mTLS): secrets derived and encrypted");

                Some(Arc::new(tokio::sync::RwLock::new(sm)))
            }
        }
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

    // Auto-detect CA cert at well-known paths if not explicitly configured.
    // Check /app/data/certs/ first (entrypoint copies mounted certs here with correct perms),
    // then /app/certs/ (direct mount).
    let ca_cert_path = config.router.ca_cert_path.clone().or_else(|| {
        let candidates = ["/app/data/certs/root_ca.crt", "/app/certs/root_ca.crt"];
        for path in &candidates {
            let p = std::path::Path::new(path);
            if p.exists() {
                tracing::info!("auto-detected CA cert at {}", p.display());
                return Some(path.to_string());
            }
        }
        None
    });

    let device_manager = if let Some(ref sm) = secrets_manager {
        let sm_read = sm.read().await;
        let has_devices = sm_read.has_devices().await.unwrap_or(false);

        if has_devices {
            // Load devices from registry
            tracing::info!("loading devices from registry");

            // Check if the primary router still uses the legacy "rb4011" ID and migrate
            if sm_read.has_device(device_manager::LEGACY_DEVICE_ID).await.unwrap_or(false) {
                // Probe router for identity — need credentials from secrets.db
                let mut probe_config = config.mikrotik_config();
                if let Ok(Some(creds)) = sm_read.get_device_credentials(device_manager::LEGACY_DEVICE_ID).await {
                    let (u, p) = creds;
                    probe_config.username = u;
                    probe_config.password = secrecy::SecretString::from(p.expose_secret().to_string());
                }
                if let Ok(probe_client) = mikrotik_core::MikrotikClient::new(probe_config) {
                    if let Ok(identity) = probe_client.test_connection().await {
                        let new_id = device_manager::slugify_device_id(&identity);
                        if new_id != device_manager::LEGACY_DEVICE_ID {
                            tracing::info!(
                                old_id = device_manager::LEGACY_DEVICE_ID,
                                new_id = %new_id,
                                identity = %identity,
                                "migrating legacy device ID"
                            );
                            match sm_read.migrate_device_id(device_manager::LEGACY_DEVICE_ID, &new_id).await {
                                Ok(count) => tracing::info!("legacy device migration complete: re-encrypted {count} secrets"),
                                Err(e) => tracing::warn!("legacy device migration failed (will retry next startup): {e}"),
                            }
                        }
                    } else {
                        tracing::warn!("router unreachable — legacy device ID migration deferred to next startup");
                    }
                }
            }

            let dm = device_manager::DeviceManager::load(
                &sm_read,
                ca_cert_path.as_deref(),
            )
            .await?;
            drop(sm_read);
            dm
        } else {
            // No devices in registry — migrate from config/env vars
            drop(sm_read);
            tracing::info!("no devices in registry, creating primary router entry from config");

            // Probe the router to auto-detect identity and model before creating the device entry
            let probe_config = config.mikrotik_config();
            let probe_client = mikrotik_core::MikrotikClient::new(probe_config)?;
            let (identity, model) = match probe_client.test_connection().await {
                Ok(name) => {
                    tracing::info!("router identity: {name}");
                    // Try to get board name for model detection
                    let board = probe_client.get::<serde_json::Value>("system/resource")
                        .await
                        .ok()
                        .and_then(|v| v.get("board-name").and_then(|b| b.as_str().map(String::from)));
                    (name, board)
                }
                Err(e) => {
                    tracing::warn!("router probe failed, using defaults: {e}");
                    ("router".to_string(), None)
                }
            };

            let device_id = device_manager::slugify_device_id(&identity);
            tracing::info!(device_id = %device_id, identity = %identity, "auto-generated device ID");

            let dm = device_manager::DeviceManager::from_config(&config, &device_id, &identity, model.as_deref())?;

            // Persist the primary router to the devices table
            let sm_read = sm.read().await;

            // Check for legacy "rb4011" device and migrate if needed
            if sm_read.has_device(device_manager::LEGACY_DEVICE_ID).await.unwrap_or(false)
                && device_id != device_manager::LEGACY_DEVICE_ID
            {
                tracing::info!(
                    old_id = device_manager::LEGACY_DEVICE_ID,
                    new_id = %device_id,
                    "migrating legacy device ID"
                );
                match sm_read.migrate_device_id(device_manager::LEGACY_DEVICE_ID, &device_id).await {
                    Ok(count) => tracing::info!("legacy device migration complete: re-encrypted {count} secrets"),
                    Err(e) => tracing::warn!("legacy device migration failed (will retry next startup): {e}"),
                }
            }

            let new_device = secrets::NewDevice {
                id: device_id.clone(),
                name: identity.clone(),
                host: config.router.host.clone(),
                port: config.router.port,
                tls: config.router.tls,
                ca_cert_path: ca_cert_path.clone(),
                device_type: "router".to_string(),
                model,
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
        // Probe router for identity; fall back to host if unreachable
        let probe_config = config.mikrotik_config();
        let identity = match mikrotik_core::MikrotikClient::new(probe_config) {
            Ok(c) => c.test_connection().await.unwrap_or_else(|_| config.router.host.clone()),
            Err(_) => config.router.host.clone(),
        };
        let device_id = device_manager::slugify_device_id(&identity);
        device_manager::DeviceManager::from_config(&config, &device_id, &identity, None)?
    };

    let device_manager = Arc::new(tokio::sync::RwLock::new(device_manager));

    // Get primary router client (backward compat — existing handlers use state.mikrotik)
    let mikrotik = {
        let dm = device_manager.read().await;
        dm.get_router_client()
            .ok_or_else(|| anyhow::anyhow!("no primary router found in device manager"))?
    };

    // Test connectivity — non-fatal so the web UI starts even if the router is unreachable.
    // Users can fix credentials via Settings → Devices without filesystem access.
    {
        let dm = device_manager.read().await;
        if let Some(entry) = dm.all_devices().into_iter().find(|d| d.record.is_primary) {
            tracing::info!(
                "connecting to router at {}:{}",
                entry.record.host,
                entry.record.port
            );
        } else {
            tracing::info!(
                "connecting to router at {}:{}",
                config.router.host,
                config.router.port
            );
        }
    }
    // Get the primary router's device ID for status updates
    let primary_id = {
        let dm = device_manager.read().await;
        dm.get_router().map(|r| r.record.id.clone()).unwrap_or_default()
    };
    match mikrotik.test_connection().await {
        Ok(name) => {
            tracing::info!("connected to router: {name}");
            let mut dm = device_manager.write().await;
            dm.set_status(
                &primary_id,
                device_manager::DeviceStatus::Online {
                    identity: name,
                },
            );
        }
        Err(e) => {
            tracing::warn!("router connection failed at startup: {e}");
            tracing::warn!("web UI will be available — fix router credentials in Settings > Devices");
            let mut dm = device_manager.write().await;
            dm.set_status(
                &primary_id,
                device_manager::DeviceStatus::Offline {
                    error: e.to_string(),
                },
            );
        }
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
        mikrotik_core::TrafficTracker::new(&data_dir.join("traffic.db"), &config.router.wan_interface)
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
    let stats_store = Arc::new(
        stats_store::StatsStore::new(&data_dir.join("stats.db"))
            .map_err(|e| anyhow::anyhow!("failed to init stats store: {e}"))?,
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

    // Load ATT&CK technique database
    let attack_techniques = Arc::new(attack_techniques::AttackTechniqueDb::load());
    tracing::info!("loaded {} ATT&CK techniques, {} deviation mappings",
        attack_techniques.techniques.len(),
        attack_techniques.deviation_mappings.len(),
    );

    // Create task supervisor
    let supervisor = TaskSupervisor::new();

    // Create serialized router request queue
    let router_queue = router_queue::RouterQueue::new(
        mikrotik.clone(),
        std::time::Duration::from_secs(config.polling.queue_gap_secs),
    );

    // Per-device API queue registry for managed switches
    let device_queues = Arc::new(tokio::sync::RwLock::new(
        device_queue_registry::DeviceQueueRegistry::new(
            std::time::Duration::from_secs(config.polling.queue_gap_secs),
        ),
    ));

    // Module infrastructure: event bus, shutdown signal, and the registry
    // populated from the empty default module list. With no modules loaded,
    // this is essentially a no-op — zero runtime overhead beyond allocating
    // the broadcast channel.
    let event_bus = ion_drift_module_host::EventBus::new(1024);
    let module_shutdown = ion_drift_module_api::ShutdownSignal::new();

    let task_spawner: std::sync::Arc<dyn ion_drift_module_api::context::TaskSpawner> =
        std::sync::Arc::new(module_adapters::SupervisorSpawner::new(supervisor.clone()));
    let secret_resolver: std::sync::Arc<
        dyn ion_drift_module_api::context::SecretResolver,
    > = std::sync::Arc::new(module_adapters::EnvSecretResolver);

    // Wire real read-only trait objects for the state stores modules can read.
    // BehaviorStore and SwitchStore are wired in v1.0; Connection / Snapshot /
    // DeviceManager remain None until cache-backed implementations land.
    let state_reads = ion_drift_module_api::context::StateReadHandles {
        behavior: Some(behavior_store.clone()
            as std::sync::Arc<dyn ion_drift_module_api::BehaviorRead>),
        switch: Some(switch_store.clone()
            as std::sync::Arc<dyn ion_drift_module_api::SwitchRead>),
        connection: None,
        snapshot: None,
        devices: None,
    };

    let host_deps = ion_drift_module_host::registry::HostDeps {
        data_dir: data_dir.clone(),
        event_bus: event_bus.clone(),
        task_spawner,
        secret_resolver,
        shutdown: module_shutdown.clone(),
        state_reads,
        modules_config: config.modules.clone(),
    };

    // The `modules::load()` pathway is retained as infrastructure only —
    // it always returns `Vec::new()`. External modules are loaded at
    // runtime via the ModuleRegistryStore (Module API v1.1), not
    // compiled in. See docs/ai/arch/modules.md.
    let mut module_registry_value =
        ion_drift_module_host::ModuleRegistry::load(modules::load(), host_deps).await;

    // Log the loaded module list at startup so operators can tell which
    // modules a binary was built with at a glance.
    {
        let summary = module_registry_value.summary();
        let names: Vec<&str> = summary
            .iter()
            .filter_map(|m| m.get("name").and_then(|v| v.as_str()))
            .collect();
        tracing::info!(
            count = summary.len(),
            modules = ?names,
            "module registry initialized"
        );
    }

    let module_registry = Arc::new(tokio::sync::RwLock::new(module_registry_value));

    // External-module registry (Module API v1.1). Shares secrets.db
    // with SecretsManager so both use the same KEK.
    let (module_registry_store, module_registry_service, module_event_dispatcher): (
        Option<Arc<modules_registry::ModuleRegistryStore>>,
        Option<Arc<modules_registry::ModuleRegistryService>>,
        Option<Arc<modules_registry::EventDispatcher>>,
    ) = if let Some(sm_lock) = &secrets_manager {
        let kek = sm_lock.read().await.kek().clone();
        let db_path = data_dir.join("secrets.db");
        match modules_registry::ModuleRegistryStore::new(&db_path, kek) {
            Ok(store) => {
                let store = Arc::new(store);
                let service = modules_registry::ModuleRegistryService::new(Arc::clone(&store))
                    .map(Arc::new)
                    .map_err(|e| {
                        tracing::warn!(error = %e, "module registry service init failed");
                        e
                    })
                    .ok();
                let dispatcher = modules_registry::EventDispatcher::new(
                    Arc::clone(&store),
                    http_client.clone(),
                    modules_registry::DispatcherConfig::default(),
                );
                tracing::info!("external module registry ready");
                (Some(store), service, Some(dispatcher))
            }
            Err(e) => {
                tracing::warn!(error = %e, "module registry store init failed");
                (None, None, None)
            }
        }
    } else {
        (None, None, None)
    };

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
        module_registry_store: module_registry_store.clone(),
        module_registry_service: module_registry_service.clone(),
        module_event_dispatcher: module_event_dispatcher.clone(),
        device_manager: device_manager.clone(),
        switch_store: switch_store.clone(),
        topology_cache: Arc::new(tokio::sync::RwLock::new(None)),
        vlan_registry: vlan_registry.clone(),
        poller_registry: Arc::new(tokio::sync::RwLock::new(
            poller_registry::PollerRegistry::new(),
        )),
        stats_store: stats_store.clone(),
        task_supervisor: supervisor,
        login_limiter: auth::LoginRateLimiter::new(),
        attack_techniques: attack_techniques.clone(),
        router_queue,
        device_queues: device_queues.clone(),
        event_bus: event_bus.clone(),
        module_registry: module_registry.clone(),
        module_shutdown: module_shutdown.clone(),
        infrastructure_snapshot: Arc::new(tokio::sync::RwLock::new(
            infrastructure_snapshot::InfrastructureSnapshotState::new(),
        )),
    };

    // Spawn all background tasks
    tasks::spawn_all(&app_state, dns_resolver);

    // Start the module event dispatcher loop if the registry came up.
    if let Some(dispatcher) = app_state.module_event_dispatcher.clone() {
        modules_registry::spawn_dispatcher_loop(dispatcher, app_state.event_bus.clone());
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
        tracing::warn!(
            "SPA directory not found at {}, only API routes available",
            web_dist.display()
        );
    }

    // Log demo mode status
    if demo::is_demo_mode() {
        tracing::warn!("DEMO MODE ACTIVE — all API responses will have sensitive data sanitized");
    }

    // Hold clones of the module shutdown signal and registry handle so we
    // can drive graceful shutdown after the serve future returns.
    let shutdown_for_graceful = module_shutdown.clone();
    let registry_for_graceful = module_registry.clone();

    // Build router and start server
    let app = routes::router(app_state, web_dist)?;
    let bind_addr = format!(
        "{}:{}",
        config.server.listen_addr, config.server.listen_port
    );
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!(version = routes::version(), "ion-drift web server listening on {bind_addr}");

    // Wait for ctrl-c (or SIGTERM via tokio::signal). On signal, drive a
    // graceful shutdown: serve future returns, then we cancel module tasks
    // and call shutdown_all on the registry with a bounded timeout.
    let shutdown_for_serve = shutdown_for_graceful.clone();
    let shutdown_signal = async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %e, "failed to listen for ctrl-c; falling back to forever");
            std::future::pending::<()>().await;
        }
        tracing::info!("shutdown signal received; draining server");
        shutdown_for_serve.cancel();
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    // Server has stopped accepting requests. Now signal modules and call
    // shutdown_all with a bounded timeout so a stuck module cannot block exit.
    shutdown_for_graceful.cancel();
    let shutdown_timeout = std::time::Duration::from_secs(5);
    tracing::info!(
        timeout_secs = shutdown_timeout.as_secs(),
        "calling module registry shutdown_all"
    );
    let shutdown_fut = async {
        let registry = registry_for_graceful.read().await;
        registry.shutdown_all().await;
    };
    if tokio::time::timeout(shutdown_timeout, shutdown_fut)
        .await
        .is_err()
    {
        tracing::warn!("module shutdown timed out; exiting anyway");
    }

    tracing::info!("ion-drift shutdown complete");
    Ok(())
}

/// Run the setup-mode server when no cert/secrets are present.
async fn run_setup_mode(config: &ServerConfig, data_dir: &std::path::Path) -> anyhow::Result<()> {
    let db_path = data_dir.join("secrets.db");

    // Generate a one-time bootstrap token to prevent unauthorized setup claims
    let bootstrap_token = {
        use rand::rngs::OsRng;
        use rand::TryRngCore;
        let mut bytes = [0u8; 16];
        OsRng.try_fill_bytes(&mut bytes).expect("OS RNG failed");
        hex::encode(bytes)
    };
    tracing::warn!("SETUP TOKEN: {bootstrap_token}");
    tracing::warn!("Use this token to complete the setup wizard. It is required to prevent unauthorized access.");

    let setup_state = setup::SetupState {
        db_path,
        router_username: config.router.username.clone(),
        tls_config: config.tls.clone(),
        oidc_bootstrap: config.oidc.as_ref().and_then(|o| o.bootstrap.clone()),
        ca_cert_path: config.oidc.as_ref().and_then(|o| o.ca_cert_path.clone()).unwrap_or_default(),
        certwarden_base_url: config.certwarden.base_url.clone(),
        certwarden_cert_name: config.certwarden.cert_name.clone(),
        bootstrap_token: Some(bootstrap_token),
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

    // Bind to configured listen address so the setup wizard is accessible in Docker
    let bind_addr = format!("{}:{}", config.server.listen_addr, config.server.listen_port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("ion-drift setup server listening on {bind_addr}");
    tracing::info!("navigate to http://{bind_addr}/setup to configure secrets");

    axum::serve(listener, app).await?;
    Ok(())
}

/// Run the local-auth setup-mode server when no KEK cache or local users exist.
///
/// Presents a form to create the initial admin account, derives the KEK from the
/// password, caches it with a machine key, and exits for Docker/systemd restart.
async fn run_local_setup_mode(config: &ServerConfig, data_dir: &std::path::Path) -> anyhow::Result<()> {
    // Generate a one-time bootstrap token to prevent unauthorized setup claims
    let bootstrap_token = {
        use rand::rngs::OsRng;
        use rand::TryRngCore;
        let mut bytes = [0u8; 16];
        OsRng.try_fill_bytes(&mut bytes).expect("OS RNG failed");
        hex::encode(bytes)
    };
    tracing::warn!("SETUP TOKEN: {bootstrap_token}");
    tracing::warn!("Use this token to complete the setup wizard. It is required to prevent unauthorized access.");

    let state = setup::LocalSetupState {
        db_path: data_dir.join("secrets.db"),
        bootstrap_token: Some(bootstrap_token),
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

    // Bind to configured listen address so the setup wizard is accessible in Docker
    let bind_addr = format!("{}:{}", config.server.listen_addr, config.server.listen_port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("ion-drift local setup server listening on {bind_addr}");
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
