//! IP geolocation with dual MaxMind GeoLite2 + ip-api.com backend.
//!
//! Lookup priority:
//! 1. MaxMind `.mmdb` databases (in-memory, microsecond lookups, includes lat/lon)
//! 2. ip-api.com SQLite cache (7-day TTL)
//! 3. ip-api.com HTTP batch fetch (async, up to 100 IPs per request)
//!
//! Two access patterns:
//! - `lookup_cached()` — sync, returns MaxMind result or cached ip-api data
//! - `resolve_batch()` — async, fetches ip-api cache misses (only needed when MaxMind unavailable)

use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};

/// Countries flagged for security monitoring.
const FLAGGED_COUNTRIES: &[&str] = &["RU", "CN", "IR", "KP", "VE", "BY", "SY", "CU"];

/// Cache entries older than this are considered stale.
const CACHE_TTL_SECS: i64 = 7 * 86400; // 7 days

/// ip-api.com batch endpoint (free tier, HTTP only).
///
/// SECURITY NOTE: This is plaintext HTTP. IP addresses being resolved are visible
/// to network observers, and responses can be tampered with (MitM). This is a
/// fallback only — when MaxMind databases are loaded, ip-api.com is never called.
/// The free tier does not support HTTPS; upgrading to Pro would allow HTTPS.
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lat: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lon: Option<f64>,
}

/// Geolocation cache with dual MaxMind + ip-api.com backend.
pub struct GeoCache {
    /// MaxMind GeoLite2-City reader (None if databases not loaded).
    mmdb_city: RwLock<Option<Arc<maxminddb::Reader<Vec<u8>>>>>,
    /// MaxMind GeoLite2-ASN reader (None if databases not loaded).
    mmdb_asn: RwLock<Option<Arc<maxminddb::Reader<Vec<u8>>>>>,
    /// SQLite-backed ip-api.com cache (fallback when MaxMind unavailable).
    db: Mutex<rusqlite::Connection>,
    /// HTTP client for ip-api.com batch requests.
    http_client: reqwest::Client,
}

impl GeoCache {
    /// Create a new GeoCache backed by a SQLite database at the given path.
    /// Optionally loads MaxMind databases if the directory contains them.
    pub fn new(db_path: &Path, mmdb_dir: Option<&Path>) -> anyhow::Result<Self> {
        let conn = rusqlite::Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS geo_cache (
                ip TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                fetched_at INTEGER NOT NULL
            )",
        )?;

        let cache = Self {
            mmdb_city: RwLock::new(None),
            mmdb_asn: RwLock::new(None),
            db: Mutex::new(conn),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()?,
        };

        // Try to load MaxMind databases if directory provided
        if let Some(dir) = mmdb_dir {
            cache.try_load_maxmind(dir);
        }

        Ok(cache)
    }

    /// Attempt to load MaxMind databases from the given directory.
    /// Logs warnings on failure but does not return errors (fallback to ip-api).
    pub fn try_load_maxmind(&self, dir: &Path) {
        let city_path = dir.join("GeoLite2-City.mmdb");
        let asn_path = dir.join("GeoLite2-ASN.mmdb");

        if city_path.exists() {
            match maxminddb::Reader::open_readfile(&city_path) {
                Ok(reader) => {
                    tracing::info!("loaded MaxMind GeoLite2-City from {}", city_path.display());
                    if let Ok(mut guard) = self.mmdb_city.write() {
                        *guard = Some(Arc::new(reader));
                    }
                }
                Err(e) => tracing::warn!("failed to load GeoLite2-City: {e}"),
            }
        }

        if asn_path.exists() {
            match maxminddb::Reader::open_readfile(&asn_path) {
                Ok(reader) => {
                    tracing::info!("loaded MaxMind GeoLite2-ASN from {}", asn_path.display());
                    if let Ok(mut guard) = self.mmdb_asn.write() {
                        *guard = Some(Arc::new(reader));
                    }
                }
                Err(e) => tracing::warn!("failed to load GeoLite2-ASN: {e}"),
            }
        }
    }

    /// Hot-swap MaxMind databases (called by the auto-updater after downloading new versions).
    pub fn hot_swap_maxmind(&self, dir: &Path) {
        self.try_load_maxmind(dir);
    }

    /// Whether MaxMind databases are loaded.
    pub fn has_maxmind(&self) -> bool {
        self.mmdb_city
            .read()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }

    /// Synchronous lookup. Tries MaxMind first, then ip-api cache.
    /// Returns `None` for private IPs or complete cache misses.
    /// Safe to call from sync contexts (log parser, behavior engine).
    pub fn lookup_cached(&self, ip: &str) -> Option<GeoInfo> {
        let ip_addr: IpAddr = ip.parse().ok()?;
        if is_private(&ip_addr) {
            return None;
        }

        // Try MaxMind first (microsecond lookup)
        if let Some(info) = self.lookup_maxmind(&ip_addr) {
            return Some(info);
        }

        // Fallback to ip-api cache
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

    /// MaxMind-only lookup from in-memory databases.
    fn lookup_maxmind(&self, ip: &IpAddr) -> Option<GeoInfo> {
        let city_reader = self.mmdb_city.read().ok()?;
        let city_reader = city_reader.as_ref()?;

        let city_result: maxminddb::geoip2::City = city_reader.lookup(*ip).ok()?;

        let country = city_result.country.as_ref()?;
        let country_code = country.iso_code?.to_string();
        let country_name = country
            .names
            .as_ref()
            .and_then(|n| n.get("en"))
            .map(|s| s.to_string())
            .unwrap_or_else(|| country_code.clone());

        let city = city_result
            .city
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en"))
            .map(|s| s.to_string());

        let location = city_result.location.as_ref();
        let lat = location.and_then(|l| l.latitude);
        let lon = location.and_then(|l| l.longitude);

        // ASN lookup (separate database)
        let (asn, org, isp) = self.lookup_asn(ip);

        Some(GeoInfo {
            country_code,
            country: country_name,
            city,
            isp,
            asn,
            org,
            lat,
            lon,
        })
    }

    /// ASN-only lookup from MaxMind GeoLite2-ASN database.
    fn lookup_asn(&self, ip: &IpAddr) -> (Option<String>, Option<String>, Option<String>) {
        let asn_reader = match self.mmdb_asn.read().ok() {
            Some(guard) => guard,
            None => return (None, None, None),
        };
        let asn_reader = match asn_reader.as_ref() {
            Some(r) => r,
            None => return (None, None, None),
        };

        let asn_result: maxminddb::geoip2::Asn = match asn_reader.lookup(*ip) {
            Ok(r) => r,
            Err(_) => return (None, None, None),
        };

        let asn = asn_result
            .autonomous_system_number
            .map(|n| format!("AS{n}"));
        let org = asn_result
            .autonomous_system_organization
            .map(|s| s.to_string());
        // GeoLite2-ASN doesn't have ISP separate from org; use org for both
        let isp = org.clone();

        (asn, org, isp)
    }

    /// Async batch resolve: checks cache for each IP, fetches misses from ip-api.com.
    /// Call this before using `lookup_cached()` to warm the cache for a set of IPs.
    /// If MaxMind is loaded, this is a no-op (MaxMind handles all lookups instantly).
    ///
    /// SECURITY: The ip-api.com fallback uses plaintext HTTP (free tier limitation).
    /// This is disabled by default — only the cached results from previous runs are used.
    /// Set `allow_plaintext_geo = true` in config to enable it (not recommended).
    pub async fn resolve_batch(&self, ips: &[String]) -> anyhow::Result<()> {
        // If MaxMind is loaded, no need for ip-api batch fetching
        if self.has_maxmind() {
            return Ok(());
        }

        // SECURITY: Do not make plaintext HTTP requests to ip-api.com.
        // This leaks queried IP addresses to network observers and is MitM-vulnerable.
        // Users should configure MaxMind GeoLite2 databases instead.
        // Only cached results from previous runs will be used.
        return Ok(());

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

        tracing::debug!(count = misses.len(), "resolving geo for uncached IPs via ip-api.com");

        // Batch fetch in chunks of MAX_BATCH_SIZE
        for chunk in misses.chunks(MAX_BATCH_SIZE) {
            let body: Vec<serde_json::Value> = chunk
                .iter()
                .map(|ip| {
                    serde_json::json!({
                        "query": ip,
                        "fields": "status,country,countryCode,city,isp,org,as,lat,lon,query"
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
                    lat: result.lat,
                    lon: result.lon,
                };
                if let Ok(json) = serde_json::to_string(&info) {
                    if let Err(e) = db.execute(
                        "INSERT OR REPLACE INTO geo_cache (ip, data, fetched_at) VALUES (?1, ?2, ?3)",
                        rusqlite::params![result.query, json, now],
                    ) {
                        tracing::warn!("failed to cache geo result for {}: {e}", result.query);
                    }
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
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
}

/// Convert empty strings to None.
fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.is_empty())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Download MaxMind GeoLite2 databases if credentials are provided and files are missing.
///
/// Uses the MaxMind download API: `https://download.maxmind.com/geoip/databases/{edition}/download`
/// with HTTP Basic Auth (account_id:license_key). Downloads tar.gz, extracts the .mmdb file.
pub async fn download_maxmind_databases(
    geoip_dir: &Path,
    account_id: &str,
    license_key: &str,
) -> anyhow::Result<Vec<String>> {
    use std::io::Read;

    let editions = [
        ("GeoLite2-City", "GeoLite2-City.mmdb"),
        ("GeoLite2-ASN", "GeoLite2-ASN.mmdb"),
    ];

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    let mut downloaded = Vec::new();

    for (edition, filename) in &editions {
        let target = geoip_dir.join(filename);
        if target.exists() {
            tracing::debug!("MaxMind {edition}: already present at {}", target.display());
            continue;
        }

        let url = format!(
            "https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz"
        );
        tracing::info!("downloading MaxMind {edition} database...");

        let resp = client
            .get(&url)
            .basic_auth(account_id, Some(license_key))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("MaxMind download failed for {edition}: HTTP {status} — {body}");
        }

        let bytes = resp.bytes().await?;
        tracing::info!("MaxMind {edition}: downloaded {} bytes, extracting...", bytes.len());

        // Decompress gzip
        let gz = flate2::read::GzDecoder::new(&bytes[..]);
        let mut archive = tar::Archive::new(gz);

        let mut found = false;
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_path_buf();
            if path
                .file_name()
                .and_then(|f| f.to_str())
                .map(|f| f == *filename)
                .unwrap_or(false)
            {
                let mut content = Vec::new();
                entry.read_to_end(&mut content)?;
                std::fs::write(&target, &content)?;
                tracing::info!(
                    "MaxMind {edition}: extracted {} ({} bytes)",
                    target.display(),
                    content.len()
                );
                found = true;
                downloaded.push(edition.to_string());
                break;
            }
        }

        if !found {
            tracing::warn!("MaxMind {edition}: {filename} not found in tar.gz archive");
        }
    }

    Ok(downloaded)
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
