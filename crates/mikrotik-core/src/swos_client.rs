//! SwOS HTTP API client for Mikrotik switches running SwOS.
//!
//! SwOS uses an undocumented HTTP API with `.b` endpoints that return
//! JavaScript-like object notation (not valid JSON). This module handles
//! HTTP Digest authentication, response parsing, and data extraction.

use reqwest::Client;
use serde::Deserialize;
use tracing::debug;

use crate::error::MikrotikError;

// ─── Data Types ──────────────────────────────────────────────────

/// System information from `/sys.b`.
#[derive(Debug, Clone)]
pub struct SwosSystem {
    pub identity: String,
    pub mac_address: String,
    pub firmware_version: String,
    pub board_name: String,
    pub uptime_secs: u64,
}

/// Per-port link status from `/link.b`.
#[derive(Debug, Clone)]
pub struct SwosLink {
    pub port_index: u8,
    pub port_name: String,
    pub enabled: bool,
    pub link_up: bool,
    pub speed: Option<String>,
}

/// Dynamic host (MAC) table entry from `/!dhost.b`.
#[derive(Debug, Clone)]
pub struct SwosHost {
    pub mac_address: String,
    pub vlan_id: Option<u16>,
    pub port_index: u8,
}

/// Per-port traffic statistics from `/stats.b`.
#[derive(Debug, Clone)]
pub struct SwosPortStats {
    pub port_index: u8,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

/// VLAN table entry from `/vlan.b`.
#[derive(Debug, Clone)]
pub struct SwosVlanEntry {
    pub vlan_id: u16,
    pub name: String,
    pub member_ports: Vec<u8>,
}

// ─── Client ──────────────────────────────────────────────────────

/// HTTP client for SwOS switches.
///
/// Handles HTTP Digest authentication and the custom response format.
#[derive(Clone)]
pub struct SwosClient {
    host: String,
    port: u16,
    username: String,
    password: String,
    http: Client,
}

impl SwosClient {
    /// Create a new SwOS client. Does not make any network requests.
    pub fn new(host: String, port: u16, username: String, password: String) -> Self {
        // SwOS is HTTP/1.0 — disable connection pooling to avoid keep-alive issues.
        // Each digest auth flow requires two requests; connection reuse confuses SwOS.
        let http = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(15))
            .pool_max_idle_per_host(0)
            .http1_only()
            .build()
            .expect("failed to build HTTP client");

        Self {
            host,
            port,
            username,
            password,
            http,
        }
    }

    fn base_url(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }

    /// Fetch a `.b` endpoint with HTTP Digest authentication.
    ///
    /// SwOS uses HTTP Digest auth: first request gets 401 with a nonce,
    /// second request includes the computed digest response.
    async fn fetch(&self, path: &str) -> Result<String, MikrotikError> {
        let url = format!("{}{}", self.base_url(), path);
        tracing::debug!(url = %url, path = %path, "SwOS fetch: sending initial request");

        // First request — expect 401 with WWW-Authenticate header.
        // Send Connection: close since SwOS is HTTP/1.0.
        let resp = self.http.get(&url).header("Connection", "close").send().await.map_err(|e| {
            tracing::error!(url = %url, error = %e, "SwOS fetch: request failed");
            e
        })?;

        let status = resp.status();
        tracing::debug!(url = %url, status = %status, "SwOS fetch: initial response");

        if status == reqwest::StatusCode::OK {
            return Ok(resp.text().await?);
        }

        if status != reqwest::StatusCode::UNAUTHORIZED {
            tracing::error!(url = %url, status = %status.as_u16(), "SwOS fetch: unexpected status (expected 401)");
            return Err(MikrotikError::RouterOs {
                status: status.as_u16(),
                message: format!("unexpected status from {path}"),
                detail: None,
            });
        }

        // Log all response headers for debugging
        for (name, value) in resp.headers() {
            tracing::debug!(header = %name, value = ?value, "SwOS 401 response header");
        }

        // Parse WWW-Authenticate header to extract realm and nonce
        let www_auth = resp
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                tracing::error!("SwOS fetch: no WWW-Authenticate header in 401 response");
                MikrotikError::AuthFailed
            })?
            .to_string();

        // Drain the 401 response body to fully close the connection.
        // SwOS is HTTP/1.0 — the body is terminated by connection close,
        // so we must consume it before making a new request.
        drop(resp.bytes().await);

        tracing::debug!(www_authenticate = %www_auth, "SwOS fetch: parsing digest challenge");

        let realm = extract_quoted_value(&www_auth, "realm")
            .ok_or_else(|| {
                tracing::error!(header = %www_auth, "SwOS fetch: no realm in WWW-Authenticate");
                MikrotikError::AuthFailed
            })?;
        let nonce = extract_quoted_value(&www_auth, "nonce")
            .ok_or_else(|| {
                tracing::error!(header = %www_auth, "SwOS fetch: no nonce in WWW-Authenticate");
                MikrotikError::AuthFailed
            })?;

        tracing::debug!(realm = %realm, nonce = %nonce, "SwOS fetch: parsed challenge");

        // Compute MD5 Digest auth response (RFC 2617, qop=auth)
        let cnonce: String = format!("{:016x}", rand::random::<u64>());
        let nc = "00000001";

        let ha1_input = format!("{}:{}:{}", self.username, realm, self.password);
        let ha1 = format!("{:x}", md5::compute(&ha1_input));
        let ha2_input = format!("GET:{}", path);
        let ha2 = format!("{:x}", md5::compute(&ha2_input));
        let resp_input = format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, cnonce, ha2);
        let response_hash = format!("{:x}", md5::compute(&resp_input));

        tracing::debug!(
            ha1_input = %ha1_input,
            ha1 = %ha1,
            ha2_input = %ha2_input,
            ha2 = %ha2,
            resp_input = %resp_input,
            response = %response_hash,
            cnonce = %cnonce,
            "SwOS fetch: computed digest"
        );

        let auth_header = format!(
            r#"Digest username="{}", realm="{}", nonce="{}", uri="{}", qop=auth, nc={}, cnonce="{}", response="{}""#,
            self.username, realm, nonce, path, nc, cnonce, response_hash
        );

        tracing::debug!(authorization = %auth_header, "SwOS fetch: sending authenticated request");

        // Second request with Authorization (new connection, Connection: close)
        let resp = self
            .http
            .get(&url)
            .header("Authorization", &auth_header)
            .header("Connection", "close")
            .send()
            .await
            .map_err(|e| {
                tracing::error!(url = %url, error = %e, "SwOS fetch: auth request failed");
                e
            })?;

        let auth_status = resp.status();
        tracing::debug!(url = %url, status = %auth_status, "SwOS fetch: auth response");

        // Log response headers on failure
        if auth_status != reqwest::StatusCode::OK {
            for (name, value) in resp.headers() {
                tracing::debug!(header = %name, value = ?value, "SwOS auth response header");
            }
        }

        if auth_status == reqwest::StatusCode::UNAUTHORIZED {
            tracing::error!(
                url = %url,
                auth_header = %auth_header,
                "SwOS fetch: still 401 after auth — digest rejected"
            );
            return Err(MikrotikError::AuthFailed);
        }

        if !auth_status.is_success() {
            tracing::error!(url = %url, status = %auth_status.as_u16(), "SwOS fetch: non-success after auth");
            return Err(MikrotikError::RouterOs {
                status: auth_status.as_u16(),
                message: format!("request to {path} failed"),
                detail: None,
            });
        }

        let body = resp.text().await?;
        tracing::debug!(url = %url, body_len = body.len(), "SwOS fetch: success");
        Ok(body)
    }

    /// Test connectivity by fetching system info. Returns the device identity.
    pub async fn test_connection(&self) -> Result<String, MikrotikError> {
        let sys = self.get_system().await?;
        Ok(sys.identity)
    }

    /// Fetch system information from `/sys.b`.
    pub async fn get_system(&self) -> Result<SwosSystem, MikrotikError> {
        let raw = self.fetch("/sys.b").await?;
        debug!(host = %self.host, "sys.b: {} bytes", raw.len());

        let json = transform_swos_to_json(&raw);
        let val: serde_json::Value = serde_json::from_str(&json)
            .map_err(|e| MikrotikError::Deserialize(format!("sys.b parse: {e}")))?;

        let identity = val
            .get("id")
            .and_then(|v| v.as_str())
            .map(decode_hex_string)
            .unwrap_or_default();

        let mac_raw = val
            .get("mac")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let mac_address = format_mac(mac_raw);

        let firmware_version = val
            .get("ver")
            .and_then(|v| v.as_str())
            .map(decode_hex_string)
            .unwrap_or_default();

        let board_name = val
            .get("brd")
            .and_then(|v| v.as_str())
            .map(decode_hex_string)
            .unwrap_or_default();

        let uptime_cs = val.get("upt").and_then(|v| v.as_u64()).unwrap_or(0);
        let uptime_secs = uptime_cs / 100;

        Ok(SwosSystem {
            identity,
            mac_address,
            firmware_version,
            board_name,
            uptime_secs,
        })
    }

    /// Fetch port link status from `/link.b`.
    pub async fn get_links(&self) -> Result<Vec<SwosLink>, MikrotikError> {
        let raw = self.fetch("/link.b").await?;
        debug!(host = %self.host, "link.b: {} bytes", raw.len());

        let json = transform_swos_to_json(&raw);
        let val: serde_json::Value = serde_json::from_str(&json)
            .map_err(|e| MikrotikError::Deserialize(format!("link.b parse: {e}")))?;

        let port_count = val.get("prt").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
        let enabled_mask = val.get("en").and_then(|v| v.as_u64()).unwrap_or(0);
        let link_mask = val.get("lnk").and_then(|v| v.as_u64()).unwrap_or(0);

        let names = val.get("nm").and_then(|v| v.as_array());
        let speeds = val.get("spd").and_then(|v| v.as_array());

        let mut links = Vec::with_capacity(port_count as usize);

        for i in 0..port_count {
            let port_name = names
                .and_then(|arr| arr.get(i as usize))
                .and_then(|v| v.as_str())
                .map(decode_hex_string)
                .unwrap_or_else(|| format!("Port{}", i + 1));

            let enabled = (enabled_mask >> i) & 1 == 1;
            let link_up = (link_mask >> i) & 1 == 1;

            let speed = speeds
                .and_then(|arr| arr.get(i as usize))
                .and_then(|v| v.as_u64())
                .and_then(decode_speed);

            links.push(SwosLink {
                port_index: i,
                port_name,
                enabled,
                link_up,
                speed: if link_up { speed } else { None },
            });
        }

        Ok(links)
    }

    /// Fetch dynamic host (MAC) table from `/!dhost.b`.
    pub async fn get_hosts(&self) -> Result<Vec<SwosHost>, MikrotikError> {
        let raw = self.fetch("/!dhost.b").await?;
        debug!(host = %self.host, "!dhost.b: {} bytes", raw.len());

        if raw.trim().is_empty() || raw.trim() == "[]" {
            return Ok(Vec::new());
        }

        let json = transform_swos_to_json(&raw);
        let entries: Vec<DhostEntry> = serde_json::from_str(&json)
            .map_err(|e| MikrotikError::Deserialize(format!("!dhost.b parse: {e}")))?;

        let hosts: Vec<SwosHost> = entries
            .into_iter()
            .map(|e| {
                let mac_address = format_mac(&e.adr);
                let vlan_id = if e.vid > 0 { Some(e.vid as u16) } else { None };

                SwosHost {
                    mac_address,
                    vlan_id,
                    port_index: e.prt as u8,
                }
            })
            .collect();

        Ok(hosts)
    }

    /// Fetch per-port traffic statistics from `/stats.b`.
    pub async fn get_stats(&self) -> Result<Vec<SwosPortStats>, MikrotikError> {
        let raw = self.fetch("/stats.b").await?;
        debug!(host = %self.host, "stats.b: {} bytes", raw.len());

        let json = transform_swos_to_json(&raw);
        let val: serde_json::Value = serde_json::from_str(&json)
            .map_err(|e| MikrotikError::Deserialize(format!("stats.b parse: {e}")))?;

        // rx/tx bytes use paired low/high 32-bit fields
        let rb = get_u64_array(&val, "rb");
        let rbh = get_u64_array(&val, "rbh");
        let tb = get_u64_array(&val, "tb");
        let tbh = get_u64_array(&val, "tbh");
        let rtp = get_u64_array(&val, "rtp");
        let ttp = get_u64_array(&val, "ttp");

        let count = rb.len();
        let mut stats = Vec::with_capacity(count);

        for i in 0..count {
            let rx_lo = *rb.get(i).unwrap_or(&0);
            let rx_hi = *rbh.get(i).unwrap_or(&0);
            let tx_lo = *tb.get(i).unwrap_or(&0);
            let tx_hi = *tbh.get(i).unwrap_or(&0);

            stats.push(SwosPortStats {
                port_index: i as u8,
                rx_bytes: (rx_hi << 32) | rx_lo,
                tx_bytes: (tx_hi << 32) | tx_lo,
                rx_packets: *rtp.get(i).unwrap_or(&0),
                tx_packets: *ttp.get(i).unwrap_or(&0),
            });
        }

        Ok(stats)
    }

    /// Fetch VLAN table from `/vlan.b`.
    pub async fn get_vlans(&self) -> Result<Vec<SwosVlanEntry>, MikrotikError> {
        let raw = self.fetch("/vlan.b").await?;
        debug!(host = %self.host, "vlan.b: {} bytes", raw.len());

        if raw.trim().is_empty() || raw.trim() == "[]" {
            return Ok(Vec::new());
        }

        let json = transform_swos_to_json(&raw);
        let entries: Vec<VlanRawEntry> = serde_json::from_str(&json)
            .map_err(|e| MikrotikError::Deserialize(format!("vlan.b parse: {e}")))?;

        let vlans: Vec<SwosVlanEntry> = entries
            .into_iter()
            .map(|e| {
                let name = decode_hex_string(&e.nm);
                let member_ports = decode_bitmask(e.mbr as u64);

                SwosVlanEntry {
                    vlan_id: e.vid as u16,
                    name,
                    member_ports,
                }
            })
            .collect();

        Ok(vlans)
    }
}

// ─── Raw deserialization types ───────────────────────────────────

#[derive(Deserialize)]
struct DhostEntry {
    adr: String,
    #[serde(default)]
    vid: u64,
    #[serde(default)]
    prt: u64,
}

#[derive(Deserialize)]
struct VlanRawEntry {
    vid: u64,
    nm: String,
    mbr: u64,
}

// ─── Helper Functions ────────────────────────────────────────────

/// Decode a hex-encoded UTF-8 string (replicates the SwOS `Fa()` JS function).
///
/// Input: `"4d542d333130"` → Output: `"MT-310"`
fn decode_hex_string(hex: &str) -> String {
    let mut result = String::new();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| {
            if i + 2 <= hex.len() {
                u8::from_str_radix(&hex[i..i + 2], 16).ok()
            } else {
                None
            }
        })
        .collect();

    // Decode as UTF-8, stopping at null byte
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == 0 {
            break;
        }

        if b < 0x80 {
            result.push(b as char);
            i += 1;
        } else if b < 0xE0 && i + 1 < bytes.len() {
            let cp = ((b as u32 & 0x1F) << 6) | (bytes[i + 1] as u32 & 0x3F);
            if let Some(c) = char::from_u32(cp) {
                result.push(c);
            }
            i += 2;
        } else if b < 0xF0 && i + 2 < bytes.len() {
            let cp = ((b as u32 & 0x0F) << 12)
                | ((bytes[i + 1] as u32 & 0x3F) << 6)
                | (bytes[i + 2] as u32 & 0x3F);
            if let Some(c) = char::from_u32(cp) {
                result.push(c);
            }
            i += 3;
        } else {
            i += 1;
        }
    }

    result
}

/// Format a raw hex MAC string into colon-separated uppercase.
///
/// Input: `"6c1ff7289c5b"` → Output: `"6C:1F:F7:28:9C:5B"`
fn format_mac(hex: &str) -> String {
    if hex.len() < 12 {
        return hex.to_uppercase();
    }
    let hex = hex.to_uppercase();
    format!(
        "{}:{}:{}:{}:{}:{}",
        &hex[0..2],
        &hex[2..4],
        &hex[4..6],
        &hex[6..8],
        &hex[8..10],
        &hex[10..12]
    )
}

/// Decode a bitmask into a list of set bit positions (0-based).
///
/// Input: `0x03a1` → `[0, 5, 7, 8, 9]` (bits 0,5,7,8,9 are set)
fn decode_bitmask(val: u64) -> Vec<u8> {
    let mut ports = Vec::new();
    for i in 0..64u8 {
        if (val >> i) & 1 == 1 {
            ports.push(i);
        }
    }
    ports
}

/// Decode speed code to human-readable string.
fn decode_speed(code: u64) -> Option<String> {
    match code {
        0x00 => Some("10M".to_string()),
        0x01 => Some("100M".to_string()),
        0x02 => Some("100M".to_string()),
        0x03 => Some("1G".to_string()),
        0x04 => Some("2.5G".to_string()),
        0x05 => Some("2.5G".to_string()),
        0x06 => Some("5G".to_string()),
        0x07 => Some("10G".to_string()),
        _ => None,
    }
}

/// Extract a `u64` array from a JSON value by field name.
fn get_u64_array(val: &serde_json::Value, field: &str) -> Vec<u64> {
    val.get(field)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|v| v.as_u64().unwrap_or(0))
                .collect()
        })
        .unwrap_or_default()
}

/// Extract a quoted value from a Digest auth header.
///
/// Input: `Digest realm="CSS310-8G+2S+", nonce="abc"`, key: `realm`
/// Output: `Some("CSS310-8G+2S+")`
fn extract_quoted_value(header: &str, key: &str) -> Option<String> {
    let pattern = format!("{}=\"", key);
    let start = header.find(&pattern)? + pattern.len();
    let end = header[start..].find('"')? + start;
    Some(header[start..end].to_string())
}

/// Transform SwOS JavaScript-like response to valid JSON.
///
/// SwOS returns responses like:
/// ```text
/// {id:'4d542d333130',mac:'d401c3698125',ver:'322e3138',upt:0x2d910435,en:0x03ff}
/// ```
///
/// This function converts it to valid JSON:
/// ```text
/// {"id":"4d542d333130","mac":"d401c3698125","ver":"322e3138","upt":764936245,"en":1023}
/// ```
///
/// Transformations:
/// 1. Replace hex integers `0x[0-9a-fA-F]+` with decimal equivalents
/// 2. Replace single-quoted strings with double-quoted strings
/// 3. Add double quotes around unquoted property names
fn transform_swos_to_json(input: &str) -> String {
    let input = input.trim();
    if input.is_empty() {
        return "{}".to_string();
    }

    let mut result = String::with_capacity(input.len() * 2);
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let ch = chars[i];

        // Handle hex integers: 0x...
        if ch == '0' && i + 1 < len && chars[i + 1] == 'x' {
            let start = i + 2;
            let mut end = start;
            while end < len && chars[end].is_ascii_hexdigit() {
                end += 1;
            }
            if end > start {
                let hex_str: String = chars[start..end].iter().collect();
                // Parse as u64 to handle large values
                match u64::from_str_radix(&hex_str, 16) {
                    Ok(val) => result.push_str(&val.to_string()),
                    Err(_) => {
                        // Fallback: keep as-is in a string
                        result.push_str("\"0x");
                        result.push_str(&hex_str);
                        result.push('"');
                    }
                }
                i = end;
            } else {
                result.push(ch);
                i += 1;
            }
            continue;
        }

        // Handle single-quoted strings → double-quoted
        if ch == '\'' {
            result.push('"');
            i += 1;
            while i < len && chars[i] != '\'' {
                if chars[i] == '"' {
                    result.push('\\');
                    result.push('"');
                } else {
                    result.push(chars[i]);
                }
                i += 1;
            }
            result.push('"');
            if i < len {
                i += 1; // skip closing quote
            }
            continue;
        }

        // Handle unquoted property names (after { or ,)
        if ch.is_ascii_alphabetic() || ch == '_' {
            // Check if this is a property name (followed by a colon)
            let start = i;
            while i < len && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let name: String = chars[start..i].iter().collect();

            // Skip whitespace
            let mut peek = i;
            while peek < len && chars[peek].is_ascii_whitespace() {
                peek += 1;
            }

            if peek < len && chars[peek] == ':' {
                // It's a property name — quote it
                result.push('"');
                result.push_str(&name);
                result.push('"');
            } else {
                // It's a bare identifier (like true/false/null) — keep as-is
                result.push_str(&name);
            }
            continue;
        }

        result.push(ch);
        i += 1;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hex_string() {
        assert_eq!(decode_hex_string("4d542d333130"), "MT-310");
        assert_eq!(decode_hex_string("322e3138"), "2.18");
        assert_eq!(
            decode_hex_string("4352533331302d38472b32532b"),
            "CRS310-8G+2S+"
        );
        assert_eq!(decode_hex_string(""), "");
    }

    #[test]
    fn test_format_mac() {
        assert_eq!(format_mac("d401c3698125"), "D4:01:C3:69:81:25");
        assert_eq!(format_mac("6c1ff7289c5b"), "6C:1F:F7:28:9C:5B");
    }

    #[test]
    fn test_decode_bitmask() {
        // 0x03a1 = binary 1110100001 = bits 0,5,7,8,9
        assert_eq!(decode_bitmask(0x03a1), vec![0, 5, 7, 8, 9]);
        // 0x03ff = all 10 bits
        assert_eq!(
            decode_bitmask(0x03ff),
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        );
        assert_eq!(decode_bitmask(0), Vec::<u8>::new());
    }

    #[test]
    fn test_transform_swos_simple() {
        let input = "{id:'4d542d333130',upt:0x2d910435}";
        let json = transform_swos_to_json(input);
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["id"].as_str().unwrap(), "4d542d333130");
        assert_eq!(val["upt"].as_u64().unwrap(), 0x2d910435);
    }

    #[test]
    fn test_transform_swos_array() {
        let input = "[{adr:'6c1ff7289c5b',vid:0x0019,prt:0x06}]";
        let json = transform_swos_to_json(input);
        let val: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(val.len(), 1);
        assert_eq!(val[0]["adr"].as_str().unwrap(), "6c1ff7289c5b");
        assert_eq!(val[0]["vid"].as_u64().unwrap(), 25);
        assert_eq!(val[0]["prt"].as_u64().unwrap(), 6);
    }

    #[test]
    fn test_transform_swos_nested_array() {
        let input = "{spd:[0x07,0x01,0x03],nm:['506f727431','506f727432']}";
        let json = transform_swos_to_json(input);
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        let spd = val["spd"].as_array().unwrap();
        assert_eq!(spd[0].as_u64().unwrap(), 7);
        assert_eq!(spd[1].as_u64().unwrap(), 1);
        let nm = val["nm"].as_array().unwrap();
        assert_eq!(nm[0].as_str().unwrap(), "506f727431");
    }
}
