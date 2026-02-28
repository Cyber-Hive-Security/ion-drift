pub mod arp;
pub mod behavior;
pub mod connections;
pub mod devices;
pub mod firewall;
pub mod history;
pub mod identity;
pub mod interfaces;
pub mod ip;
pub mod logs;
pub mod metrics;
pub mod network_map_status;
pub mod settings;
pub mod switch_data;
pub mod system;
pub mod topology;
pub mod traffic;
pub mod vlan_activity;
pub mod vlan_flows;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, post, put};
use axum_extra::extract::CookieJar;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::auth;
use crate::state::AppState;

/// Shared error handler for RouterOS API errors.
/// Logs the full error server-side but returns a generic message to the client.
pub(crate) fn api_error(e: mikrotik_core::MikrotikError) -> Response {
    tracing::error!("router API error: {e}");
    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({ "error": "upstream router communication error" })),
    )
        .into_response()
}

/// Internal server error helper for serialization or other internal failures.
pub(crate) fn internal_error(context: &str, e: impl std::fmt::Display) -> Response {
    tracing::error!("{context}: {e}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": "internal server error" })),
    )
        .into_response()
}

/// Extract the origin (scheme + host) from a full URL.
fn extract_origin(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let rest = &url[scheme_end + 3..];
        if let Some(path_start) = rest.find('/') {
            return url[..scheme_end + 3 + path_start].to_string();
        }
    }
    url.to_string()
}

/// Health check endpoint — no auth required.
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

/// Global auth guard middleware for all /api/* routes.
/// This is belt-and-suspenders on top of per-handler `RequireAuth` extractors —
/// ensures no API route can accidentally be exposed without authentication.
async fn require_auth_layer(
    State(state): State<AppState>,
    jar: CookieJar,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let session_id = jar
        .get(&state.config.session.cookie_name)
        .map(|c| c.value().to_string());

    let valid = session_id
        .as_deref()
        .and_then(|id| state.sessions.get(id))
        .is_some();

    if !valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "authentication required" })),
        )
            .into_response();
    }

    next.run(request).await
}

/// Build the full Axum router with all routes and middleware.
///
/// `web_dist` is the path to the SPA's built assets (e.g. `web/dist`).
/// If the directory doesn't exist, the fallback serves a plain 404.
pub fn router(state: AppState, web_dist: std::path::PathBuf) -> Router {
    // SPA fallback: serve static files from web/dist/,
    // fall back to index.html for client-side routing.
    let index_html = web_dist.join("index.html");
    let spa = ServeDir::new(&web_dist)
        .not_found_service(ServeFile::new(index_html));

    // Derive CORS allowed origin from the OIDC redirect URI
    let origin = extract_origin(&state.config.oidc.redirect_uri);
    let cors = CorsLayer::new()
        .allow_origin(
            origin
                .parse::<HeaderValue>()
                .unwrap_or_else(|e| {
                    panic!(
                        "FATAL: failed to parse CORS origin '{}' from redirect_uri: {} \
                         — fix oidc.redirect_uri in config",
                        origin, e
                    );
                }),
        )
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_credentials(true);

    // API routes — protected by global auth middleware layer
    let api_routes = Router::new()
        // System
        .route("/system/resources", get(system::resources))
        .route("/system/identity", get(system::identity))
        // Interfaces
        .route("/interfaces", get(interfaces::list))
        .route("/interfaces/vlans", get(interfaces::vlans))
        // IP
        .route("/ip/addresses", get(ip::addresses))
        .route("/ip/routes", get(ip::routes))
        .route("/ip/dhcp-leases", get(ip::dhcp_leases))
        .route("/ip/pools", get(ip::pools))
        .route("/ip/dhcp-servers", get(ip::dhcp_servers))
        // Firewall
        .route("/firewall/filter", get(firewall::filter))
        .route("/firewall/nat", get(firewall::nat))
        .route("/firewall/mangle", get(firewall::mangle))
        .route("/firewall/drops", get(firewall::drops))
        // Connections
        .route("/connections/summary", get(connections::summary))
        .route("/connections/page", get(connections::page))
        .route("/connections/history", get(connections::history))
        .route("/connections/geo-summary", get(connections::geo_summary))
        .route("/connections/port-summary", get(connections::port_summary))
        .route("/connections/port-summary-classified", get(connections::port_summary_classified))
        .route("/connections/city-summary", get(connections::city_summary))
        .route("/connections/stats", get(connections::history_stats))
        // ARP + enhanced endpoints
        .route("/ip/arp", get(arp::list))
        .route("/ip/dhcp-leases-status", get(arp::dhcp_leases_status))
        .route("/ip/pool-utilization", get(arp::pool_utilization))
        // Logs
        .route("/logs", get(logs::list))
        // Traffic
        .route("/traffic", get(traffic::current))
        .route("/traffic/live", get(traffic::live))
        .route("/traffic/vlan-flows", get(vlan_flows::vlan_flows))
        .route("/traffic/vlan-activity", get(vlan_activity::vlan_activity))
        // Metrics
        .route("/metrics/history", get(metrics::history))
        .route("/metrics/drops", get(metrics::drops_history))
        .route("/metrics/connections", get(metrics::connections_history))
        .route("/metrics/vlans", get(metrics::vlans_history))
        .route("/metrics/log-trends", get(metrics::log_trends))
        // Network map
        .route("/network-map/status", get(network_map_status::status))
        // Behavior
        .route("/behavior/overview", get(behavior::overview))
        .route("/behavior/vlan/{vlan_id}", get(behavior::vlan_detail))
        .route("/behavior/device/{mac}", get(behavior::device_detail))
        .route("/behavior/anomalies", get(behavior::anomalies))
        .route("/behavior/anomalies/{id}/resolve", post(behavior::resolve_anomaly))
        .route("/behavior/alerts", get(behavior::alerts))
        .route("/behavior/anomaly-links", get(behavior::anomaly_links))
        .route("/behavior/anomaly-links/port/{protocol}/{port}", get(behavior::anomaly_links_by_port))
        .route("/behavior/anomaly-links/device/{mac}", get(behavior::anomaly_links_by_device))
        .route("/behavior/anomaly-links/{id}/resolve", post(behavior::resolve_anomaly_link))
        .route("/behavior/port-baseline", get(connections::port_baseline_status))
        .route("/behavior/port-baseline/compute", post(connections::compute_port_baselines))
        // History (snapshots)
        .route("/history/snapshots", get(history::list_snapshots))
        .route("/history/snapshot/{week}/{snapshot_type}", get(history::get_snapshot))
        // Settings
        .route("/settings/secrets", get(settings::secrets_status).put(settings::update_secrets))
        .route("/settings/secrets/session/regenerate", post(settings::regenerate_session))
        .route("/settings/encryption", get(settings::encryption_status))
        .route("/settings/cert", get(settings::cert_status))
        .route("/settings/syslog", get(connections::syslog_status))
        .route("/settings/geoip", get(connections::geoip_status))
        // Devices (CRUD)
        .route("/devices", get(devices::list_devices).post(devices::create_device))
        .route("/devices/test", post(devices::test_connection))
        .route("/devices/{id}", get(devices::get_device).put(devices::update_device).delete(devices::delete_device))
        .route("/devices/{id}/test", post(devices::test_device))
        // Device-specific data
        .route("/devices/{id}/resources", get(switch_data::device_resources))
        .route("/devices/{id}/interfaces", get(switch_data::device_interfaces))
        .route("/devices/{id}/ports", get(switch_data::device_ports))
        .route("/devices/{id}/mac-table", get(switch_data::device_mac_table))
        .route("/devices/{id}/neighbors", get(switch_data::device_neighbors))
        .route("/devices/{id}/vlans", get(switch_data::device_vlans))
        .route("/devices/{id}/port-roles", get(switch_data::device_port_roles))
        // Network-wide correlation data
        .route("/network/identities", get(switch_data::network_identities))
        .route("/network/mac-table", get(switch_data::network_mac_table))
        .route("/network/neighbors", get(switch_data::network_neighbors))
        .route("/network/port-roles", get(switch_data::network_port_roles))
        // Identity management
        .route("/network/identities/stats", get(identity::identity_stats))
        .route("/network/identities/review-queue", get(identity::review_queue))
        .route("/network/identities/{mac}", put(identity::update_identity))
        .route("/network/identities/bulk-confirm", post(identity::bulk_confirm))
        // Observed services (passive discovery)
        .route("/network/services", get(identity::observed_services))
        // Nmap scan routes removed — replaced by passive_discovery (connection tracking)
        // Network topology
        .route("/network/topology", get(topology::get_topology))
        .route("/network/topology/refresh", post(topology::refresh_topology))
        .route("/network/topology/positions", get(topology::get_positions))
        .route("/network/topology/positions/{nodeId}", put(topology::update_position).delete(topology::reset_position))
        // Global auth middleware for all API routes
        .layer(middleware::from_fn_with_state(state.clone(), require_auth_layer));

    Router::new()
        // Health check (no auth)
        .route("/health", get(health))
        // Auth routes (no RequireAuth)
        .route("/auth/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/status", get(auth::status))
        // Nest all API routes under /api with global auth layer
        .nest("/api", api_routes)
        // SPA static files (fallback for all non-API routes)
        .fallback_service(spa)
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        // Security headers
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("1; mode=block"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'"),
        ))
        .with_state(state)
}
