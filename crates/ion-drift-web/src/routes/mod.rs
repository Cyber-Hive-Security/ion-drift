pub mod firewall;
pub mod interfaces;
pub mod ip;
pub mod logs;
pub mod speedtest;
pub mod system;
pub mod traffic;

use axum::Router;
use axum::routing::{get, post};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::auth;
use crate::state::AppState;

/// Build the full Axum router with all routes and middleware.
pub fn router(state: AppState) -> Router {
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
        // Firewall
        .route("/api/firewall/filter", get(firewall::filter))
        .route("/api/firewall/nat", get(firewall::nat))
        .route("/api/firewall/mangle", get(firewall::mangle))
        // Logs
        .route("/api/logs", get(logs::list))
        // Traffic
        .route("/api/traffic", get(traffic::current))
        // Speedtest
        .route("/api/speedtest/latest", get(speedtest::latest))
        .route("/api/speedtest/history", get(speedtest::history))
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}
