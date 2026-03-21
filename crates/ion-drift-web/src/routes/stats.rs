//! Statistics and diagnostic report route handlers.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};

use crate::middleware::{RequireAdmin, RequireAuth};
use crate::state::AppState;
use super::internal_error;

// ── Known pages (validated on POST) ─────────────────────────────────

const KNOWN_PAGES: &[&str] = &[
    "dashboard",
    "interfaces",
    "ip",
    "firewall",
    "connections",
    "logs",
    "behavior",
    "investigation",
    "identity",
    "topology",
    "settings",
    "history",
    "policy",
];

// ── MAC address hashing ─────────────────────────────────────────────

/// Detect MAC address patterns (XX:XX:XX:XX:XX:XX) and replace with a
/// truncated SHA-256 hash (first 8 hex chars) to strip PII.
fn sanitize_context(context: &str) -> String {
    // Simple regex-free MAC detection: 6 groups of 2 hex chars separated by colons
    let mut result = context.to_string();
    let mac_pattern = regex_lite_mac_find(&result);
    for mac in mac_pattern {
        let hash = short_hash(&mac);
        result = result.replace(&mac, &hash);
    }
    result
}

/// Find all MAC-address-like patterns in the string.
fn regex_lite_mac_find(s: &str) -> Vec<String> {
    let mut macs = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    // MAC format: XX:XX:XX:XX:XX:XX (17 chars)
    if chars.len() < 17 {
        return macs;
    }
    let mut i = 0;
    while i + 17 <= chars.len() {
        let candidate: String = chars[i..i + 17].iter().collect();
        if is_mac_address(&candidate) {
            macs.push(candidate);
            i += 17;
        } else {
            i += 1;
        }
    }
    macs
}

fn is_mac_address(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    parts.iter().all(|p| {
        p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit())
    })
}

fn short_hash(mac: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(mac.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..4])
}

// ── POST /api/stats/page-view ───────────────────────────────────────

#[derive(Deserialize)]
pub struct PageViewRequest {
    pub page: String,
    pub context: Option<String>,
}

/// POST /api/stats/page-view — record a page navigation event.
pub async fn record_page_view(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Json(body): Json<PageViewRequest>,
) -> Response {
    // Validate page name
    if !KNOWN_PAGES.contains(&body.page.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "unknown page" })),
        )
            .into_response();
    }

    // Validate and sanitize context
    let context = match body.context {
        Some(ref ctx) if ctx.len() > 100 => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "context too long (max 100 chars)" })),
            )
                .into_response();
        }
        Some(ref ctx) => sanitize_context(ctx),
        None => String::new(),
    };

    state.stats_store.record_page_view(&body.page, &context).await;
    StatusCode::NO_CONTENT.into_response()
}

// ── GET /api/stats/page-views ───────────────────────────────────────

#[derive(Deserialize)]
pub struct PageViewsParams {
    #[serde(default = "default_days")]
    pub days: u32,
}

fn default_days() -> u32 {
    30
}

/// GET /api/stats/page-views — raw page view data for the Statistics page.
pub async fn get_page_views(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(params): Query<PageViewsParams>,
) -> Result<Json<Vec<crate::stats_store::PageViewEntry>>, Response> {
    let days = params.days.min(90);
    let entries = state
        .stats_store
        .get_page_views(days)
        .await
        .map_err(|e| internal_error("page views query", e))?;
    Ok(Json(entries))
}

// ── GET /api/stats/report ───────────────────────────────────────────

#[derive(Serialize)]
pub struct DiagnosticReport {
    pub generated_at: String,
    pub version: String,
    pub environment: EnvironmentInfo,
    pub scale: ScaleMetrics,
    pub feature_adoption: FeatureAdoption,
    pub engine_health: EngineHealth,
    pub error_summary: ErrorSummary,
    pub page_views: PageViewSummary,
}

#[derive(Serialize)]
pub struct EnvironmentInfo {
    pub version: String,
    pub data_directory: String,
    pub data_dir_size_bytes: u64,
    pub oidc_configured: bool,
    pub tls_enabled: bool,
}

#[derive(Serialize)]
pub struct ScaleMetrics {
    pub network_identity_count: i64,
    pub connection_history_rows: i64,
    pub connection_db_size_bytes: i64,
    pub vlan_config_count: usize,
    pub syslog_events_today: i64,
    pub syslog_events_week: i64,
}

#[derive(Serialize)]
pub struct FeatureAdoption {
    pub oidc_enabled: bool,
    pub alert_rule_count: usize,
    pub backbone_link_count: usize,
    pub confirmed_identity_count: i64,
    pub geoip_enabled: bool,
}

#[derive(Serialize)]
pub struct EngineHealth {
    pub behavior: BehaviorHealth,
    pub investigations: InvestigationHealth,
}

#[derive(Serialize)]
pub struct BehaviorHealth {
    pub total_devices: i64,
    pub baselined: i64,
    pub learning: i64,
    pub sparse: i64,
    pub pending_anomalies: i64,
    pub critical_anomalies: i64,
    pub warning_anomalies: i64,
}

#[derive(Serialize)]
pub struct InvestigationHealth {
    pub total: i64,
    pub benign: i64,
    pub routine: i64,
    pub suspicious: i64,
    pub threat: i64,
    pub inconclusive: i64,
}

#[derive(Serialize)]
pub struct ErrorSummary {
    // TODO: Add error counters when centralized error tracking is implemented.
    pub placeholder: String,
}

#[derive(Serialize)]
pub struct PageViewSummary {
    pub days_covered: u32,
    pub total_views: i64,
    pub by_page: Vec<PageAggregate>,
}

#[derive(Serialize)]
pub struct PageAggregate {
    pub page: String,
    pub total_views: i64,
}

/// GET /api/stats/report — generate the full diagnostic report (admin only).
pub async fn diagnostic_report(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
) -> Result<Json<DiagnosticReport>, Response> {
    let now = chrono::Utc::now();
    let version = env!("CARGO_PKG_VERSION").to_string();

    // ── Environment ──────────────────────────────────────────────
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("ion-drift");
    let data_dir_size = dir_size_bytes(&data_dir);

    let environment = EnvironmentInfo {
        version: version.clone(),
        data_directory: data_dir.display().to_string(),
        data_dir_size_bytes: data_dir_size,
        oidc_configured: state.config.has_oidc(),
        tls_enabled: !state.config.tls.client_cert.is_empty(),
    };

    // ── Scale metrics ────────────────────────────────────────────
    let identity_stats = state
        .switch_store
        .get_identity_stats()
        .await
        .map_err(|e| internal_error("identity stats", e))?;

    let conn_stats = state
        .connection_store
        .stats()
        .map_err(|e| internal_error("connection stats", e))?;

    let vlan_configs = state
        .switch_store
        .get_vlan_configs()
        .await
        .unwrap_or_default();

    let (syslog_today, syslog_week) = state
        .connection_store
        .syslog_event_counts()
        .unwrap_or((0, 0));

    let scale = ScaleMetrics {
        network_identity_count: identity_stats.total,
        connection_history_rows: conn_stats.row_count,
        connection_db_size_bytes: conn_stats.db_size_bytes,
        vlan_config_count: vlan_configs.len(),
        syslog_events_today: syslog_today,
        syslog_events_week: syslog_week,
    };

    // ── Feature adoption ─────────────────────────────────────────
    let alert_rules = crate::alerting::get_alert_rules(&state.switch_store)
        .await
        .unwrap_or_default();

    let backbone_links = state
        .switch_store
        .get_backbone_links()
        .await
        .unwrap_or_default();

    let feature_adoption = FeatureAdoption {
        oidc_enabled: state.config.has_oidc(),
        alert_rule_count: alert_rules.len(),
        backbone_link_count: backbone_links.len(),
        confirmed_identity_count: identity_stats.confirmed,
        geoip_enabled: state.geo_cache.has_maxmind(),
    };

    // ── Engine health ────────────────────────────────────────────
    let behavior_overview = state
        .behavior_store
        .overview_stats()
        .await
        .map_err(|e| internal_error("behavior overview", e))?;

    let investigation_stats = state
        .behavior_store
        .get_investigation_stats(24 * 30) // last 30 days
        .await
        .map_err(|e| internal_error("investigation stats", e))?;

    let engine_health = EngineHealth {
        behavior: BehaviorHealth {
            total_devices: behavior_overview.total_devices,
            baselined: behavior_overview.baselined_devices,
            learning: behavior_overview.learning_devices,
            sparse: behavior_overview.sparse_devices,
            pending_anomalies: behavior_overview.pending_anomalies,
            critical_anomalies: behavior_overview.critical_anomalies,
            warning_anomalies: behavior_overview.warning_anomalies,
        },
        investigations: InvestigationHealth {
            total: investigation_stats.total,
            benign: investigation_stats.benign,
            routine: investigation_stats.routine,
            suspicious: investigation_stats.suspicious,
            threat: investigation_stats.threat,
            inconclusive: investigation_stats.inconclusive,
        },
    };

    // ── Page views ───────────────────────────────────────────────
    let page_view_entries = state
        .stats_store
        .get_page_views(30)
        .await
        .unwrap_or_default();

    let total_views: i64 = page_view_entries.iter().map(|e| e.view_count).sum();

    // Aggregate by page
    let mut page_totals: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for entry in &page_view_entries {
        *page_totals.entry(entry.page.clone()).or_default() += entry.view_count;
    }
    let mut by_page: Vec<PageAggregate> = page_totals
        .into_iter()
        .map(|(page, total_views)| PageAggregate { page, total_views })
        .collect();
    by_page.sort_by(|a, b| b.total_views.cmp(&a.total_views));

    let page_views = PageViewSummary {
        days_covered: 30,
        total_views,
        by_page,
    };

    // ── Error summary (placeholder) ──────────────────────────────
    let error_summary = ErrorSummary {
        placeholder: "Error tracking not yet implemented. Future: centralized error counters.".into(),
    };

    Ok(Json(DiagnosticReport {
        generated_at: now.to_rfc3339(),
        version: version.clone(),
        environment,
        scale,
        feature_adoption,
        engine_health,
        error_summary,
        page_views,
    }))
}

/// Recursively compute directory size in bytes. Non-blocking best-effort.
fn dir_size_bytes(path: &std::path::Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let ft = entry.file_type();
            if let Ok(ft) = ft {
                if ft.is_file() {
                    total += entry.metadata().map(|m| m.len()).unwrap_or(0);
                } else if ft.is_dir() {
                    total += dir_size_bytes(&entry.path());
                }
            }
        }
    }
    total
}
