pub mod arp;
pub mod connections;
pub mod firewall;
pub mod interfaces;
pub mod ip;
pub mod logs;
pub mod metrics;
pub mod speedtest;
pub mod system;
pub mod traffic;
pub mod vlan_activity;
pub mod vlan_flows;

use axum::Router;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

use crate::auth;
use crate::state::AppState;

/// Shared error handler for RouterOS API errors.
pub(crate) fn api_error(e: mikrotik_core::MikrotikError) -> Response {
    tracing::error!("router API error: {e}");
    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({ "error": e.to_string() })),
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
                .expect("valid origin from redirect_uri"),
        )
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_credentials(true);

    Router::new()
        // Auth routes (no RequireAuth)
        .route("/auth/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/status", get(auth::status))
        // System
        .route("/api/system/resources", get(system::resources))
        .route("/api/system/identity", get(system::identity))
        // Interfaces
        .route("/api/interfaces", get(interfaces::list))
        .route("/api/interfaces/vlans", get(interfaces::vlans))
        // IP
        .route("/api/ip/addresses", get(ip::addresses))
        .route("/api/ip/routes", get(ip::routes))
        .route("/api/ip/dhcp-leases", get(ip::dhcp_leases))
        .route("/api/ip/pools", get(ip::pools))
        .route("/api/ip/dhcp-servers", get(ip::dhcp_servers))
        // Firewall
        .route("/api/firewall/filter", get(firewall::filter))
        .route("/api/firewall/nat", get(firewall::nat))
        .route("/api/firewall/mangle", get(firewall::mangle))
        .route("/api/firewall/drops", get(firewall::drops))
        // Connections
        .route("/api/connections/summary", get(connections::summary))
        .route("/api/connections/page", get(connections::page))
        // ARP + enhanced endpoints
        .route("/api/ip/arp", get(arp::list))
        .route("/api/ip/dhcp-leases-status", get(arp::dhcp_leases_status))
        .route("/api/ip/pool-utilization", get(arp::pool_utilization))
        // Logs
        .route("/api/logs", get(logs::list))
        // Traffic
        .route("/api/traffic", get(traffic::current))
        .route("/api/traffic/live", get(traffic::live))
        .route("/api/traffic/vlan-flows", get(vlan_flows::vlan_flows))
        .route("/api/traffic/vlan-activity", get(vlan_activity::vlan_activity))
        // Metrics
        .route("/api/metrics/history", get(metrics::history))
        // Speedtest
        .route("/api/speedtest/latest", get(speedtest::latest))
        .route("/api/speedtest/history", get(speedtest::history))
        .route("/api/speedtest/run", post(speedtest::run))
        .route("/api/speedtest/status", get(speedtest::status))
        // SPA static files (fallback for all non-API routes)
        .fallback_service(spa)
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}
