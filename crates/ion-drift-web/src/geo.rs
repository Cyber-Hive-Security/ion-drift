//! IP geolocation via ip-api.com batch endpoint with SQLite cache.
//!
//! Replaces the old MaxMind GeoLite2 approach. No database files to manage;
//! just HTTP calls to ip-api.com with a 7-day SQLite cache.
//!
//! Two access patterns:
//! - `lookup_cached()` — sync, returns only what's already in the cache
//! - `resolve_batch()` — async, fetches cache misses from ip-api.com

use std::net::IpAddr;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Countries flagged for security monitoring.
const FLAGGED_COUNTRIES: &[&str] = &["RU", "CN", "IR", "KP", "VE", "BY", "SY", "CU"];

/// Cache entries older than this are considered stale.
const CACHE_TTL_SECS: i64 = 7 * 86400; // 7 days

/// ip-api.com batch endpoint (free tier, HTTP only).
const BATCH_URL: &str = "http://ip-api.com/batch";

/// ip-api.com allows up to 100 IPs per batch request.
const MAX_BATCH_SIZE: usize = 100;

/// Geolocation info resolved from an IP address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub country_code: String,
    pub country: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

/// SQLite-backed geolocation cache with HTTP batch resolution.
pub struct GeoCache {
    db: Mutex<rusqlite::Connection>,
    http_client: reqwest::Client,
}

impl GeoCache {
    /// Create a new GeoCache backed by a SQLite database at the given path.
    pub fn new(db_path: &std::path::Path) -> anyhow::Result<Self> {
        let conn = rusqlite::Connection::open(db_path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS geo_cache (
                ip TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                fetched_at INTEGER NOT NULL
            )",
        )?;
        Ok(Self {
            db: Mutex::new(conn),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()?,
        })
    }

    /// Synchronous cache-only lookup. Returns `None` for private IPs or cache misses.
    /// Safe to call from sync contexts (log parser, behavior engine).
    pub fn lookup_cached(&self, ip: &str) -> Option<GeoInfo> {
        let ip_addr: IpAddr = ip.parse().ok()?;
        if is_private(&ip_addr) {
            return None;
        }
        let db = self.db.lock().ok()?;
        let now = now_unix();
        let cutoff = now - CACHE_TTL_SECS;
        let json: String = db
            .query_row(
                "SELECT data FROM geo_cache WHERE ip = ?1 AND fetched_at > ?2",
                rusqlite::params![ip, cutoff],
                |row| row.get(0),
            )
            .ok()?;
        serde_json::from_str(&json).ok()
    }

    /// Async batch resolve: checks cache for each IP, fetches misses from ip-api.com.
    /// Call this before using `lookup_cached()` to warm the cache for a set of IPs.
    pub async fn resolve_batch(&self, ips: &[String]) -> anyhow::Result<()> {
        // Filter to unique external IPs only
        let mut seen = std::collections::HashSet::new();
        let external: Vec<&str> = ips
            .iter()
            .filter_map(|ip| {
                let addr: IpAddr = ip.parse().ok()?;
                if is_private(&addr) || !seen.insert(ip.as_str()) {
                    None
                } else {
                    Some(ip.as_str())
                }
            })
            .collect();

        if external.is_empty() {
            return Ok(());
        }

        // Check which IPs are missing from cache (lock scope limited, no await)
        let misses: Vec<&str> = {
            let db = self
                .db
                .lock()
                .map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
            let now = now_unix();
            let cutoff = now - CACHE_TTL_SECS;
            external
                .into_iter()
                .filter(|ip| {
                    db.query_row(
                        "SELECT 1 FROM geo_cache WHERE ip = ?1 AND fetched_at > ?2",
                        rusqlite::params![*ip, cutoff],
                        |_| Ok(()),
                    )
                    .is_err()
                })
                .collect()
        };

        if misses.is_empty() {
            return Ok(());
        }

        tracing::debug!(count = misses.len(), "resolving geo for uncached IPs");

        // Batch fetch in chunks of MAX_BATCH_SIZE
        for chunk in misses.chunks(MAX_BATCH_SIZE) {
            let body: Vec<serde_json::Value> = chunk
                .iter()
                .map(|ip| {
                    serde_json::json!({
                        "query": ip,
                        "fields": "status,country,countryCode,city,isp,org,as,query"
                    })
                })
                .collect();

            let resp = match self.http_client.post(BATCH_URL).json(&body).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("ip-api.com batch request failed: {e}");
                    continue;
                }
            };

            if !resp.status().is_success() {
                tracing::warn!("ip-api.com returned {}", resp.status());
                continue;
            }

            let results: Vec<IpApiResponse> = match resp.json().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("failed to parse ip-api.com response: {e}");
                    continue;
                }
            };

            let now = now_unix();
            let db = self
                .db
                .lock()
                .map_err(|e| anyhow::anyhow!("db lock: {e}"))?;

            for result in results {
                if result.status != "success" {
                    continue;
                }
                let info = GeoInfo {
                    country_code: result.country_code,
                    country: result.country,
                    city: non_empty(result.city),
                    isp: non_empty(result.isp),
                    asn: result
                        .as_field
                        .as_deref()
                        .and_then(|s| s.split_whitespace().next())
                        .map(String::from),
                    org: non_empty(result.org),
                };
                if let Ok(json) = serde_json::to_string(&info) {
                    let _ = db.execute(
                        "INSERT OR REPLACE INTO geo_cache (ip, data, fetched_at) VALUES (?1, ?2, ?3)",
                        rusqlite::params![result.query, json, now],
                    );
                }
            }
        }

        Ok(())
    }

    /// Check whether a country code is in the flagged list.
    pub fn is_flagged(code: &str) -> bool {
        FLAGGED_COUNTRIES.contains(&code)
    }
}

/// ip-api.com batch response entry.
#[derive(Deserialize)]
struct IpApiResponse {
    status: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    country: String,
    #[serde(default, rename = "countryCode")]
    country_code: String,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default, rename = "as")]
    as_field: Option<String>,
}

/// Convert empty strings to None.
fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.is_empty())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Check if an IP is RFC1918 private or other reserved range.
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            octets[0] == 10
            // 172.16.0.0/12
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            // 192.168.0.0/16
            || (octets[0] == 192 && octets[1] == 168)
            // 127.0.0.0/8 (loopback)
            || octets[0] == 127
            // 169.254.0.0/16 (link-local)
            || (octets[0] == 169 && octets[1] == 254)
            // 0.0.0.0
            || v4.is_unspecified()
            // 255.255.255.255
            || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified()
            // fe80::/10 link-local
            || (v6.segments()[0] & 0xffc0) == 0xfe80
            // fc00::/7 unique local
            || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}
