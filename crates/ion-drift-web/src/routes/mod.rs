pub mod alerts;
pub mod arp;
pub mod backbone;
pub mod behavior;
pub mod neighbor_aliases;
pub mod provision;
pub mod connections;
pub mod devices;
pub mod firewall;
pub mod history;
pub mod identity;
pub mod inference;
pub mod interfaces;
pub mod ip;
pub mod logs;
pub mod metrics;
pub mod network_map_status;
pub mod sankey;
pub mod settings;
pub mod switch_data;
pub mod system;
pub mod topology;
pub mod traffic;
pub mod vlan_activity;
pub mod vlan_flows;
pub mod vlans;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
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

/// CSRF protection middleware for non-GET API endpoints.
///
/// Requires that mutating requests (POST/PUT/DELETE) include a Content-Type
/// header with `application/json`. This prevents cross-origin form submissions
/// from attaching session cookies, since HTML forms cannot set custom
/// Content-Type values beyond form-urlencoded/multipart/text-plain.
///
/// Combined with SameSite=Lax cookies and strict CORS, this provides
/// defense-in-depth against CSRF attacks.
pub(crate) async fn csrf_guard_layer(
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    if method != Method::GET && method != Method::HEAD && method != Method::OPTIONS {
        let has_body = request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map_or(false, |len| len > 0);

        if has_body {
            let ct = request
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !ct.starts_with("application/json") {
                return (
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    Json(serde_json::json!({ "error": "Content-Type must be application/json" })),
                )
                    .into_response();
            }
        }
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode, header};
    use axum::middleware;
    use axum::routing::{delete, get, options, post, put};
    use axum::Router;
    use tower::util::ServiceExt;

    use super::csrf_guard_layer;

    fn app() -> Router {
        Router::new()
            .route(
                "/x",
                get(|| async { StatusCode::OK })
                    .post(|| async { StatusCode::OK })
                    .put(|| async { StatusCode::OK })
                    .delete(|| async { StatusCode::OK })
                    .options(|| async { StatusCode::OK }),
            )
            .layer(middleware::from_fn(csrf_guard_layer))
    }

    async fn call(method: Method, content_type: Option<&str>, body: &str) -> StatusCode {
        let mut req = Request::builder().method(method).uri("/x");
        if let Some(ct) = content_type {
            req = req.header(header::CONTENT_TYPE, ct);
        }
        let req = req
            .header(header::CONTENT_LENGTH, body.len().to_string())
            .body(Body::from(body.to_string()))
            .expect("request build");
        app().oneshot(req).await.expect("response").status()
    }

    #[tokio::test]
    async fn csrf_rejects_form_urlencoded_post() {
        let status = call(
            Method::POST,
            Some("application/x-www-form-urlencoded"),
            "a=1&b=2",
        )
        .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn csrf_rejects_multipart_post() {
        let status = call(Method::POST, Some("multipart/form-data"), "payload").await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn csrf_rejects_text_plain_post() {
        let status = call(Method::POST, Some("text/plain"), "payload").await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn csrf_allows_json_post() {
        let status = call(Method::POST, Some("application/json"), "{\"x\":1}").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn csrf_allows_empty_body_post() {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/x")
            .header(header::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .expect("request");
        let status = app().oneshot(req).await.expect("response").status();
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn csrf_allows_get_requests() {
        let status = call(Method::GET, Some("text/plain"), "payload").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn csrf_allows_options_requests() {
        let status = call(Method::OPTIONS, Some("text/plain"), "payload").await;
        assert_eq!(status, StatusCode::OK);
    }
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
pub fn router(state: AppState, web_dist: std::path::PathBuf) -> anyhow::Result<Router> {
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
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to parse CORS origin '{}' from redirect_uri: {} \
                         — fix oidc.redirect_uri in config",
                        origin, e
                    )
                })?,
        )
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_credentials(true);

    // API routes — protected by global auth middleware layer
    let api_routes = Router::new()
        // System
        .route("/system/resources", get(system::resources))
        .route("/system/identity", get(system::identity))
        .route("/system/tasks", get(system::tasks))
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
        .route("/settings/map-config", get(settings::map_config))
        .route("/settings/secrets", get(settings::secrets_status).put(settings::update_secrets))
        .route("/settings/secrets/session/regenerate", post(settings::regenerate_session))
        .route("/settings/sessions", get(settings::list_sessions))
        .route("/settings/sessions/{session_id}", delete(settings::revoke_session))
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
        .route("/devices/{id}/port-list", get(switch_data::device_port_list))
        .route("/devices/{id}/mac-table", get(switch_data::device_mac_table))
        .route("/devices/{id}/neighbors", get(switch_data::device_neighbors))
        .route("/devices/{id}/vlans", get(switch_data::device_vlans))
        .route("/devices/{id}/port-roles", get(switch_data::device_port_roles))
        .route("/devices/{id}/port-utilization", get(switch_data::device_port_utilization))
        // Provisioning (Setup Wizard)
        .route("/devices/{id}/provision/plan", post(provision::plan))
        .route("/devices/{id}/provision/apply", post(provision::apply))
        .route("/devices/{id}/provision/interfaces", get(provision::interfaces))
        // Network-wide correlation data
        .route("/network/identities", get(switch_data::network_identities))
        .route("/network/mac-table", get(switch_data::network_mac_table))
        .route("/network/neighbors", get(switch_data::network_neighbors))
        .route("/network/port-roles", get(switch_data::network_port_roles))
        // Identity management
        .route("/network/identities/infrastructure", get(identity::list_infrastructure_identities))
        .route("/network/identities/stats", get(identity::identity_stats))
        .route("/network/identities/review-queue", get(identity::review_queue))
        .route("/network/identities/{mac}/fields/{field}", delete(identity::reset_identity_field))
        .route("/network/identities/{mac}", put(identity::update_identity))
        .route("/network/identities/{mac}/disposition", put(identity::set_disposition))
        .route("/network/identities/bulk-confirm", post(identity::bulk_confirm))
        .route("/network/identities/bulk-disposition", post(identity::bulk_disposition))
        // Observed services (passive discovery)
        .route("/network/services", get(identity::observed_services))
        // Port MAC bindings
        .route("/network/port-bindings", get(identity::list_port_bindings).post(identity::create_port_binding))
        .route("/network/port-bindings/{device_id}", get(identity::list_device_port_bindings))
        .route("/network/port-bindings/{device_id}/{port}", put(identity::update_port_binding).delete(identity::delete_port_binding))
        // Port violations
        .route("/network/port-violations", get(identity::list_port_violations))
        .route("/network/port-violations/{device_id}", get(identity::list_device_port_violations))
        .route("/network/port-violations/{id}/resolve", put(identity::resolve_port_violation))
        // Alerts
        .route("/alerts/rules", get(alerts::list_rules).post(alerts::create_rule))
        .route("/alerts/rules/{id}", put(alerts::update_rule).delete(alerts::delete_rule))
        .route("/alerts/status", get(alerts::status))
        .route("/alerts/history", get(alerts::history).delete(alerts::clear_history))
        .route("/alerts/channels", get(alerts::list_channels))
        .route("/alerts/channels/{channel}", put(alerts::update_channel))
        .route("/alerts/channels/{channel}/test", post(alerts::test_channel))
        // Sankey investigation
        .route("/sankey/network", get(sankey::network_overview))
        .route("/sankey/vlan/{vlan_id}", get(sankey::vlan_detail))
        .route("/sankey/device/{mac}", get(sankey::device_trace))
        .route("/sankey/device/{mac}/destination/{ip}", get(sankey::conversation_detail))
        .route("/sankey/destination/{ip}/devices", get(sankey::destination_peers))
        // Network topology
        .route("/network/topology", get(topology::get_topology))
        .route("/network/topology/refresh", post(topology::refresh_topology))
        .route("/network/topology/positions", get(topology::get_positions).put(topology::batch_update_positions))
        .route("/network/topology/positions/{nodeId}", put(topology::update_position).delete(topology::reset_position))
        .route("/network/topology/sectors", get(topology::get_sectors))
        .route("/network/topology/sectors/{vlanId}", put(topology::update_sector).delete(topology::reset_sector))
        // VLAN config
        .route("/network/vlan-config", get(vlans::list_vlan_configs))
        .route("/network/vlan-config/{vlan_id}", put(vlans::upsert_vlan_config))
        // Backbone links (manual switch interconnects)
        .route("/network/backbone-links", get(backbone::list_backbone_links).post(backbone::create_backbone_link))
        .route("/network/backbone-links/{id}", put(backbone::update_backbone_link).delete(backbone::delete_backbone_link))
        // Neighbor aliases (topology neighbor mapping/hiding)
        .route("/network/neighbor-aliases", get(neighbor_aliases::list_neighbor_aliases).post(neighbor_aliases::create_neighbor_alias))
        .route("/network/neighbor-aliases/{id}", delete(neighbor_aliases::delete_neighbor_alias))
        // Topology inference diagnostics
        .route("/network/inference/status", get(inference::inference_status))
        .route("/network/inference/states", get(inference::all_attachment_states))
        .route("/network/inference/mac/{mac}", get(inference::inference_mac_detail))
        .route("/network/inference/observations", get(inference::observation_stats))
        // Global auth middleware for all API routes
        .layer(middleware::from_fn_with_state(state.clone(), require_auth_layer))
        // CSRF protection: require application/json Content-Type on mutating requests
        .layer(middleware::from_fn(csrf_guard_layer))
        // Limit request body size to 2 MiB
        .layer(DefaultBodyLimit::max(2_097_152));

    Ok(Router::new()
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
            HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; connect-src 'self'; font-src 'self' https://fonts.gstatic.com; frame-ancestors 'none'"),
        ))
        .with_state(state))
}
