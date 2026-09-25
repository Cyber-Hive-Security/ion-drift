//! End-to-end handler tests for the DRIFT P3 graceful-degradation endpoints.
//!
//! Each endpoint is driven directly (extractors constructed by hand) against a
//! full test [`AppState`] backed by a [`MockRouter`]:
//!
//! * an **erroring** router must yield `200 OK` with `live_available: false`
//!   plus stored/empty data (never a 502);
//! * a **healthy** router must yield `200 OK` with `live_available: true` and
//!   normal live data.
//!
//! These supersede the "impractical without a harness" limitation noted in the
//! P3 work, which could only test `live_or_degrade` and the pure builders.

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::routes::network_map_status::{
    DeviceStatus, NetworkMapStatusCache, NetworkMapStatusResponse,
};
use crate::routes::{arp, connections, firewall, logs, network_map_status};
use crate::testkit::{MockRouter, test_app_state, test_session};

/// Unwrap a handler result, asserting it is the `Ok(Json(_))` (HTTP 200) arm.
/// On the error arm it reports the status, so a regression to 502 fails loudly.
fn ok_json<T>(result: Result<Json<T>, Response>) -> Json<T> {
    result.unwrap_or_else(|resp| {
        panic!("handler degraded to an error response: {}", resp.status())
    })
}

/// Confirm a `Json<T>` renders as HTTP 200.
fn assert_http_200<T: serde::Serialize>(json: Json<T>) {
    assert_eq!(json.into_response().status(), StatusCode::OK);
}

fn cached_device(ip: &str) -> DeviceStatus {
    DeviceStatus {
        ip: ip.into(),
        mac: Some("AA:BB:CC:DD:EE:99".into()),
        hostname: Some("cached-host".into()),
        manufacturer: Some("Acme".into()),
        in_arp: true,
        dhcp_status: Some("bound".into()),
        dhcp_server: Some("dhcp1".into()),
        expires_after: Some("1h".into()),
        last_seen: Some("2026-09-24T00:00:00Z".into()),
        hop_count: Some(1),
        internet_path: None,
    }
}

// ── connections::summary ──────────────────────────────────────────

#[tokio::test]
async fn connections_summary_degrades_when_router_errors() {
    let (state, _tmp) = test_app_state(MockRouter::erroring()).await;
    let json = ok_json(connections::summary(test_session(), State(state)).await);
    assert!(!json.0.live_available, "must signal degraded");
    assert_eq!(json.0.total_connections, 0, "empty store -> zero");
    assert_http_200(json);
}

#[tokio::test]
async fn connections_summary_live_when_router_healthy() {
    let (state, _tmp) = test_app_state(MockRouter::healthy()).await;
    let json = ok_json(connections::summary(test_session(), State(state)).await);
    assert!(json.0.live_available, "must signal live");
    assert_eq!(json.0.total_connections, 2);
    assert_eq!(json.0.tcp_count, 1);
    assert_eq!(json.0.udp_count, 1);
    assert_eq!(json.0.max_entries, Some(1000));
    assert_http_200(json);
}

// ── connections::page ─────────────────────────────────────────────

#[tokio::test]
async fn connections_page_degrades_when_router_errors() {
    let (state, _tmp) = test_app_state(MockRouter::erroring()).await;
    let json = ok_json(connections::page(test_session(), State(state)).await);
    assert!(!json.0.live_available);
    assert!(json.0.connections.is_empty(), "empty store -> no rows");
    assert_http_200(json);
}

#[tokio::test]
async fn connections_page_live_when_router_healthy() {
    let (state, _tmp) = test_app_state(MockRouter::healthy()).await;
    let json = ok_json(connections::page(test_session(), State(state)).await);
    assert!(json.0.live_available);
    assert_eq!(json.0.connections.len(), 1);
    assert_eq!(json.0.connections[0].protocol, "tcp");
    assert_eq!(json.0.summary.total, 1);
    assert_http_200(json);
}

// ── logs::list ────────────────────────────────────────────────────

#[tokio::test]
async fn logs_list_degrades_when_router_errors() {
    let (state, _tmp) = test_app_state(MockRouter::erroring()).await;
    let json = ok_json(logs::list(test_session(), State(state), Query(Default::default())).await);
    assert!(!json.0.live_available);
    assert!(json.0.entries.is_empty(), "no buffered logs -> empty graceful set");
    assert_http_200(json);
}

#[tokio::test]
async fn logs_list_live_when_router_healthy() {
    let (state, _tmp) = test_app_state(MockRouter::healthy()).await;
    let json = ok_json(logs::list(test_session(), State(state), Query(Default::default())).await);
    assert!(json.0.live_available);
    assert!(!json.0.entries.is_empty(), "healthy router returns log entries");
    assert_http_200(json);
}

// ── arp::list ─────────────────────────────────────────────────────

#[tokio::test]
async fn arp_list_degrades_empty_without_cache() {
    let (state, _tmp) = test_app_state(MockRouter::erroring()).await;
    let json = ok_json(arp::list(test_session(), State(state)).await);
    assert!(!json.0.live_available);
    assert!(json.0.items.is_empty(), "no cache -> empty");
    assert_http_200(json);
}

#[tokio::test]
async fn arp_list_degrades_to_cached_snapshot() {
    let (state, _tmp) = test_app_state(MockRouter::erroring()).await;
    // Seed the network-map cache so the degraded path serves stored data.
    {
        let mut cache = state.network_map_cache.write().await;
        *cache = Some(NetworkMapStatusCache {
            data: NetworkMapStatusResponse {
                devices: vec![cached_device("10.0.0.50")],
                interfaces: Vec::new(),
                timestamp: 1_700_000_000,
                live_available: true,
                as_of: None,
            },
            cached_at: std::time::Instant::now(),
            prev_bytes: HashMap::new(),
        });
    }
    let json = ok_json(arp::list(test_session(), State(state)).await);
    assert!(!json.0.live_available, "still marked degraded");
    assert_eq!(json.0.items.len(), 1, "stored ARP row served");
    assert_eq!(json.0.items[0].address, "10.0.0.50");
    assert!(json.0.as_of.is_some(), "as_of derived from snapshot timestamp");
    assert_http_200(json);
}

#[tokio::test]
async fn arp_list_live_when_router_healthy() {
    let (state, _tmp) = test_app_state(MockRouter::healthy()).await;
    let json = ok_json(arp::list(test_session(), State(state)).await);
    assert!(json.0.live_available);
    assert_eq!(json.0.items.len(), 1);
    assert_eq!(json.0.items[0].address, "10.0.0.2");
    assert_http_200(json);
}

// ── arp::dhcp_leases_status ───────────────────────────────────────

#[tokio::test]
async fn dhcp_leases_status_degrades_when_router_errors() {
    let (state, _tmp) = test_app_state(MockRouter::erroring()).await;
    let json = ok_json(arp::dhcp_leases_status(test_session(), State(state)).await);
    assert!(!json.0.live_available);
    assert!(json.0.items.is_empty());
    assert_http_200(json);
}

#[tokio::test]
async fn dhcp_leases_status_live_when_router_healthy() {
    let (state, _tmp) = test_app_state(MockRouter::healthy()).await;
    let json = ok_json(arp::dhcp_leases_status(test_session(), State(state)).await);
    assert!(json.0.live_available);
    assert_eq!(json.0.items.len(), 1);
    // Lease 10.0.0.2 is present in the ARP table -> "active".
    assert_eq!(json.0.items[0].arp_status, "active");
    assert_http_200(json);
}

// ── arp::pool_utilization ─────────────────────────────────────────

#[tokio::test]
async fn pool_utilization_degrades_when_router_errors() {
    let (state, _tmp) = test_app_state(MockRouter::erroring()).await;
    let json = ok_json(arp::pool_utilization(test_session(), State(state)).await);
    assert!(!json.0.live_available);
    assert!(json.0.items.is_empty(), "no cache fallback -> empty");
    assert_http_200(json);
}

#[tokio::test]
async fn pool_utilization_live_when_router_healthy() {
    let (state, _tmp) = test_app_state(MockRouter::healthy()).await;
    let json = ok_json(arp::pool_utilization(test_session(), State(state)).await);
    assert!(json.0.live_available);
    assert_eq!(json.0.items.len(), 1);
    let entry = &json.0.items[0];
    assert_eq!(entry.pool_name, "pool1");
    assert_eq!(entry.bound_count, 1);
    assert_eq!(entry.active_on_network, 1);
    assert_http_200(json);
}

// ── network_map_status::status ────────────────────────────────────

#[tokio::test]
async fn network_map_status_degrades_when_router_errors() {
    let (state, _tmp) = test_app_state(MockRouter::erroring()).await;
    let json = ok_json(network_map_status::status(test_session(), State(state)).await);
    assert!(!json.0.live_available);
    assert!(json.0.devices.is_empty());
    assert_eq!(json.0.timestamp, 0, "empty snapshot when no cache");
    assert_http_200(json);
}

#[tokio::test]
async fn network_map_status_live_when_router_healthy() {
    let (state, _tmp) = test_app_state(MockRouter::healthy()).await;
    let json = ok_json(network_map_status::status(test_session(), State(state)).await);
    assert!(json.0.live_available);
    assert!(!json.0.devices.is_empty(), "healthy router yields devices");
    assert_eq!(json.0.interfaces.len(), 1);
    assert_http_200(json);
}

// ── firewall::filter ──────────────────────────────────────────────

#[tokio::test]
async fn firewall_filter_degrades_empty_without_cache() {
    let (state, _tmp) = test_app_state(MockRouter::erroring()).await;
    let json = ok_json(firewall::filter(test_session(), State(state), Query(Default::default())).await);
    assert!(!json.0.live_available);
    assert!(json.0.items.is_empty(), "empty rules cache -> empty");
    assert_http_200(json);
}

#[tokio::test]
async fn firewall_filter_degrades_to_cached_rules() {
    let (state, _tmp) = test_app_state(MockRouter::erroring()).await;
    // Seed the last-known filter-rule cache.
    {
        let rule: mikrotik_core::resources::firewall::FilterRule =
            serde_json::from_value(serde_json::json!({
                ".id": "*z1",
                "chain": "forward",
                "action": "accept",
            }))
            .unwrap();
        let mut cache = state.firewall_rules_cache.write().await;
        cache.0 = vec![rule];
    }
    let json = ok_json(firewall::filter(test_session(), State(state), Query(Default::default())).await);
    assert!(!json.0.live_available, "still marked degraded");
    assert_eq!(json.0.items.len(), 1, "served last-known rules");
    assert_http_200(json);
}

#[tokio::test]
async fn firewall_filter_live_when_router_healthy() {
    let (state, _tmp) = test_app_state(MockRouter::healthy()).await;
    let json = ok_json(firewall::filter(test_session(), State(state), Query(Default::default())).await);
    assert!(json.0.live_available);
    assert_eq!(json.0.items.len(), 2);
    assert_http_200(json);
}

#[tokio::test]
async fn firewall_filter_live_respects_chain_query() {
    let (state, _tmp) = test_app_state(MockRouter::healthy()).await;
    let filter = crate::routes::firewall::ChainFilter {
        chain: Some("forward".into()),
    };
    let json = ok_json(firewall::filter(test_session(), State(state), Query(filter)).await);
    assert!(json.0.live_available);
    assert_eq!(json.0.items.len(), 1, "only the forward-chain rule");
    assert!(json.0.items.iter().all(|r| r.chain == "forward"));
    assert_http_200(json);
}
