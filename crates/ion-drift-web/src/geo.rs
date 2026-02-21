//! GeoIP lookup using MaxMind GeoLite2-Country database.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use serde::Serialize;

/// Countries flagged for security monitoring.
const FLAGGED_COUNTRIES: &[&str] = &["RU", "CN", "IR", "KP", "VE", "BY", "SY", "CU"];

/// Country information resolved from an IP address.
#[derive(Debug, Clone, Serialize)]
pub struct CountryInfo {
    pub code: String,
    pub name: String,
}

/// GeoIP database wrapper (optional — gracefully disabled if mmdb not present).
#[derive(Clone)]
pub struct GeoDb {
    reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
}

impl GeoDb {
    /// Try to load a GeoLite2-Country mmdb file. Returns a no-op GeoDb if path
    /// is None or the file can't be loaded.
    pub fn load(path: Option<&str>) -> Arc<Self> {
        let reader = path.and_then(|p| {
            if !Path::new(p).exists() {
                tracing::warn!("GeoIP database not found at {p}, geo features disabled");
                return None;
            }
            match maxminddb::Reader::open_readfile(p) {
                Ok(r) => {
                    tracing::info!("GeoIP database loaded from {p}");
                    Some(Arc::new(r))
                }
                Err(e) => {
                    tracing::warn!("failed to load GeoIP database: {e}");
                    None
                }
            }
        });

        Arc::new(Self { reader })
    }

    /// Whether the GeoIP database is available.
    pub fn is_available(&self) -> bool {
        self.reader.is_some()
    }

    /// Look up an IP address, returning country info.
    /// Returns None for private/reserved IPs or if no database is loaded.
    pub fn lookup(&self, ip_str: &str) -> Option<CountryInfo> {
        let reader = self.reader.as_ref()?;

        let ip: IpAddr = ip_str.parse().ok()?;

        // Skip private/reserved IPs
        if is_private(&ip) {
            return None;
        }

        let result: maxminddb::geoip2::Country = reader.lookup(ip).ok()?;
        let country = result.country?;
        let code = country.iso_code?.to_string();
        let name = country
            .names
            .as_ref()
            .and_then(|n| n.get("en"))
            .map(|s| s.to_string())
            .unwrap_or_else(|| code.clone());

        Some(CountryInfo { code, name })
    }

    /// Check whether a country code is in the flagged list.
    pub fn is_flagged(code: &str) -> bool {
        FLAGGED_COUNTRIES.contains(&code)
    }
}

/// Check if an IP is RFC1918 private or other reserved range.
fn is_private(ip: &IpAddr) -> bool {
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
