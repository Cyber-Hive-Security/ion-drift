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
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};

/// Cache entries older than this are considered stale.
const CACHE_TTL_SECS: i64 = 7 * 86400; // 7 days

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

pub trait GeoProvider: Send + Sync {
    fn lookup(&self, ip: &IpAddr) -> Option<GeoInfo>;
    fn try_load(&self, dir: &Path);
    fn is_loaded(&self) -> bool;
}

pub struct MaxMindProvider {
    mmdb_city: RwLock<Option<Arc<maxminddb::Reader<Vec<u8>>>>>,
    mmdb_asn: RwLock<Option<Arc<maxminddb::Reader<Vec<u8>>>>>,
}

impl MaxMindProvider {
    pub fn new() -> Self {
        Self {
            mmdb_city: RwLock::new(None),
            mmdb_asn: RwLock::new(None),
        }
    }

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
        let isp = org.clone();

        (asn, org, isp)
    }
}

impl GeoProvider for MaxMindProvider {
    fn lookup(&self, ip: &IpAddr) -> Option<GeoInfo> {
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

    fn try_load(&self, dir: &Path) {
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

    fn is_loaded(&self) -> bool {
        self.mmdb_city.read().map(|g| g.is_some()).unwrap_or(false)
    }
}

/// Geolocation cache with MaxMind GeoLite2 backend and SQLite lookup cache.
pub struct GeoCache {
    /// Lookup provider for MaxMind-backed geolocation.
    provider: Arc<dyn GeoProvider>,
    /// SQLite-backed lookup cache.
    db: Mutex<rusqlite::Connection>,
    /// Countries highlighted for monitoring (uppercase ISO 3166-1 alpha-2).
    /// Wrapped in RwLock so the settings page can update at runtime.
    monitored_regions: RwLock<std::collections::HashSet<String>>,
}

impl GeoCache {
    /// Create a new GeoCache backed by a SQLite database at the given path.
    /// Optionally loads MaxMind databases if the directory contains them.
    /// `warning_countries` overrides the default flagged-country list (uppercase ISO codes).
    pub fn new(db_path: &Path, mmdb_dir: Option<&Path>, warning_countries: Vec<String>) -> anyhow::Result<Self> {
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
            provider: Arc::new(MaxMindProvider::new()),
            db: Mutex::new(conn),
            monitored_regions: RwLock::new(warning_countries.into_iter().collect()),
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
        self.provider.try_load(dir);
    }

    /// Hot-swap MaxMind databases (called by the auto-updater after downloading new versions).
    pub fn hot_swap_maxmind(&self, dir: &Path) {
        self.try_load_maxmind(dir);
    }

    /// Whether MaxMind databases are loaded.
    pub fn has_maxmind(&self) -> bool {
        self.provider.is_loaded()
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
        if let Some(info) = self.provider.lookup(&ip_addr) {
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

    /// Async batch resolve: checks cache for each IP, fetches misses from ip-api.com.
    /// Call this before using `lookup_cached()` to warm the cache for a set of IPs.
    /// If MaxMind is loaded, this is a no-op (MaxMind handles all lookups instantly).
    ///
    /// SECURITY: The ip-api.com fallback uses plaintext HTTP (free tier limitation).
    /// This is disabled by default — only the cached results from previous runs are used.
    /// Set `allow_plaintext_geo = true` in config to enable it (not recommended).
    pub async fn resolve_batch(&self, _ips: &[String]) -> anyhow::Result<()> {
        // MaxMind handles all lookups instantly — no batch fetching needed.
        // The ip-api.com fallback has been removed for security reasons:
        // it uses plaintext HTTP which leaks queried IPs and is MitM-vulnerable.
        // Users should configure MaxMind GeoLite2 databases instead.
        Ok(())
    }

    /// Check whether a country code is in the monitored regions list.
    pub fn is_flagged(&self, code: &str) -> bool {
        self.monitored_regions
            .read()
            .map(|set| set.contains(code))
            .unwrap_or(false)
    }

    /// Get the current monitored region codes.
    pub fn get_monitored_regions(&self) -> Vec<String> {
        self.monitored_regions
            .read()
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Replace the monitored regions list at runtime.
    pub fn set_monitored_regions(&self, codes: Vec<String>) {
        if let Ok(mut set) = self.monitored_regions.write() {
            *set = codes.into_iter().collect();
        }
    }
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
