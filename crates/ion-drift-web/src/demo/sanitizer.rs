use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

/// Deterministic sanitizer for demo mode. Uses hash-based mapping so the same
/// input always produces the same fake output within a process lifetime.
/// This preserves visual consistency across pages/refreshes.
pub struct DemoSanitizer {
    /// Stable seed for hashing (fixed per process).
    seed: [u8; 16],
    /// Cached IP mappings for consistency.
    ip_cache: Mutex<HashMap<String, String>>,
    /// Cached MAC mappings.
    mac_cache: Mutex<HashMap<String, String>>,
    /// Cached hostname mappings.
    hostname_cache: Mutex<HashMap<String, String>>,
    /// Counter for generating sequential hostnames.
    hostname_counter: Mutex<u32>,
}

impl DemoSanitizer {
    pub fn new() -> Self {
        Self {
            seed: *b"ion-drift-demo!1",
            ip_cache: Mutex::new(HashMap::new()),
            mac_cache: Mutex::new(HashMap::new()),
            hostname_cache: Mutex::new(HashMap::new()),
            hostname_counter: Mutex::new(0),
        }
    }

    /// Sanitize a JSON value tree in place.
    pub fn sanitize_value(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(s) => {
                *s = self.sanitize_string(s);
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    self.sanitize_value(item);
                }
            }
            serde_json::Value::Object(map) => {
                // Process each key-value pair, using key context to guide sanitization
                let keys: Vec<String> = map.keys().cloned().collect();
                for key in keys {
                    if let Some(val) = map.get_mut(&key) {
                        self.sanitize_field(&key, val);
                    }
                }
            }
            _ => {}
        }
    }

    /// Sanitize a field based on its key name for more targeted replacement.
    fn sanitize_field(&self, key: &str, value: &mut serde_json::Value) {
        let key_lower = key.to_lowercase();
        let key_lower = key_lower.as_str();

        match value {
            serde_json::Value::String(s) => {
                // Skip empty strings and very short values
                if s.is_empty() {
                    return;
                }

                // Context-aware sanitization based on field name
                if is_ip_field(key_lower) {
                    // Could be "10.20.25.1/24" (CIDR) or plain IP
                    *s = self.sanitize_ip_or_cidr(s);
                } else if is_mac_field(key_lower) {
                    *s = self.sanitize_mac(s);
                } else if is_hostname_field(key_lower) {
                    *s = self.sanitize_hostname(s);
                } else if is_identity_field(key_lower) {
                    *s = "Demo-Router".to_string();
                } else if is_isp_field(key_lower) {
                    *s = self.sanitize_isp(s);
                } else if is_comment_field(key_lower) {
                    *s = self.sanitize_comment(s);
                } else if is_interface_list_field(key_lower) {
                    // Keep interface names like "ether1", "bridge1" — they're generic
                } else {
                    // For unknown fields, check if the value looks like an IP or MAC
                    *s = self.sanitize_string(s);
                }
            }
            serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                self.sanitize_value(value);
            }
            _ => {}
        }
    }

    /// General-purpose string sanitizer that detects and replaces IPs and MACs.
    fn sanitize_string(&self, s: &str) -> String {
        // Check for IP address pattern (with optional CIDR)
        if looks_like_ip_or_cidr(s) {
            return self.sanitize_ip_or_cidr(s);
        }
        // Check for MAC address pattern
        if looks_like_mac(s) {
            return self.sanitize_mac(s);
        }
        s.to_string()
    }

    /// Sanitize an IP address or CIDR notation string.
    fn sanitize_ip_or_cidr(&self, s: &str) -> String {
        if let Some((ip, prefix)) = s.split_once('/') {
            let sanitized_ip = self.sanitize_ip(ip);
            format!("{sanitized_ip}/{prefix}")
        } else {
            self.sanitize_ip(s)
        }
    }

    /// Map a real IP to a deterministic fake IP.
    fn sanitize_ip(&self, ip: &str) -> String {
        {
            let cache = self.ip_cache.lock().unwrap();
            if let Some(cached) = cache.get(ip) {
                return cached.clone();
            }
        }

        let parsed: Ipv4Addr = match ip.parse() {
            Ok(addr) => addr,
            Err(_) => return ip.to_string(), // Not a valid IP, return as-is
        };

        let octets = parsed.octets();
        let hash = self.hash_bytes(ip.as_bytes());

        let fake = if is_private_ip(&octets) {
            // All private IPs → 10.249.VLAN.host
            // Preserves VLAN = 3rd octet convention, only host octet is randomized
            let o4 = (hash[0] as u16 % 254 + 1) as u8;
            Ipv4Addr::new(10, 249, octets[2], o4)
        } else if parsed.is_loopback() {
            parsed // Keep loopback as-is
        } else {
            // Public IP → map to a different public-looking IP
            // Use documentation ranges: 198.51.100.0/24, 203.0.113.0/24
            let range = hash[3] % 2;
            let o4 = (hash[0] as u16 % 254 + 1) as u8;
            if range == 0 {
                Ipv4Addr::new(198, 51, 100, o4)
            } else {
                Ipv4Addr::new(203, 0, 113, o4)
            }
        };

        let result = fake.to_string();
        self.ip_cache.lock().unwrap().insert(ip.to_string(), result.clone());
        result
    }

    /// Map a real MAC to a deterministic fake MAC.
    fn sanitize_mac(&self, mac: &str) -> String {
        {
            let cache = self.mac_cache.lock().unwrap();
            if let Some(cached) = cache.get(mac) {
                return cached.clone();
            }
        }

        let hash = self.hash_bytes(mac.as_bytes());

        // Determine separator (: or -)
        let sep = if mac.contains('-') { '-' } else { ':' };

        // Generate fake MAC with locally-administered bit set (x2:xx:xx:xx:xx:xx)
        // This avoids colliding with real OUI assignments
        let fake = format!(
            "{:02X}{sep}{:02X}{sep}{:02X}{sep}{:02X}{sep}{:02X}{sep}{:02X}",
            (hash[0] & 0xFC) | 0x02, // Set locally administered bit, clear multicast
            hash[1],
            hash[2],
            hash[3],
            hash[4],
            hash[5],
        );

        self.mac_cache.lock().unwrap().insert(mac.to_string(), fake.clone());
        fake
    }

    /// Map a hostname to a generic demo name.
    fn sanitize_hostname(&self, hostname: &str) -> String {
        if hostname.is_empty() {
            return hostname.to_string();
        }

        {
            let cache = self.hostname_cache.lock().unwrap();
            if let Some(cached) = cache.get(hostname) {
                return cached.clone();
            }
        }

        let mut counter = self.hostname_counter.lock().unwrap();
        *counter += 1;
        let n = *counter;

        // Generate a plausible-looking hostname
        let prefixes = [
            "workstation", "laptop", "server", "printer", "phone",
            "tablet", "desktop", "camera", "switch", "ap",
        ];
        let hash = self.hash_bytes(hostname.as_bytes());
        let prefix = prefixes[hash[0] as usize % prefixes.len()];
        let fake = format!("{prefix}-{n:03}");

        self.hostname_cache.lock().unwrap().insert(hostname.to_string(), fake.clone());
        fake
    }

    /// Replace ISP/ASN/org names with generic ones.
    fn sanitize_isp(&self, isp: &str) -> String {
        if isp.is_empty() {
            return isp.to_string();
        }
        let hash = self.hash_bytes(isp.as_bytes());
        let isps = [
            "Global Telecom Corp",
            "NetServe Communications",
            "Pacific Internet Services",
            "Atlantic Broadband Inc",
            "Digital Connect LLC",
            "Metro Fiber Networks",
            "CloudPath Solutions",
            "Horizon Data Services",
        ];
        isps[hash[0] as usize % isps.len()].to_string()
    }

    /// Sanitize comment fields — remove any IPs or hostnames embedded in comments.
    fn sanitize_comment(&self, comment: &str) -> String {
        if comment.is_empty() {
            return comment.to_string();
        }
        // Replace any embedded IPs in the comment
        let mut result = comment.to_string();
        // Simple regex-free approach: scan for IP-like patterns
        let words: Vec<&str> = comment.split_whitespace().collect();
        for word in &words {
            let clean = word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != ':');
            if looks_like_ip_or_cidr(clean) {
                let sanitized = self.sanitize_ip_or_cidr(clean);
                result = result.replace(clean, &sanitized);
            } else if looks_like_mac(clean) {
                let sanitized = self.sanitize_mac(clean);
                result = result.replace(clean, &sanitized);
            }
        }
        result
    }

    /// HMAC-like hash using SHA-256 with the fixed seed.
    fn hash_bytes(&self, input: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.seed);
        hasher.update(input);
        hasher.finalize().into()
    }
}

// ── Pattern detection helpers ───────────────────────────────────

fn is_ip_field(key: &str) -> bool {
    matches!(
        key,
        "address" | "src_address" | "dst_address" | "src-address" | "dst-address"
            | "gateway" | "dst-address" | "network" | "best_ip" | "current_ip"
            | "target_ip" | "ip" | "local-address" | "remote-address"
            | "active-address" | "server-address" | "dns-server"
            | "ntp-server" | "dhcp_gateway" | "target"
    )
}

fn is_mac_field(key: &str) -> bool {
    matches!(
        key,
        "mac-address" | "mac_address" | "mac" | "orig-mac-address"
            | "src-mac-address" | "dst-mac-address" | "active-mac-address"
    )
}

fn is_hostname_field(key: &str) -> bool {
    matches!(
        key,
        "host-name" | "hostname" | "host_name" | "name"
            | "server-name" | "dns-name" | "comment-hostname"
    )
}

fn is_identity_field(key: &str) -> bool {
    matches!(key, "identity" | "system_identity" | "router_name")
}

fn is_isp_field(key: &str) -> bool {
    matches!(key, "isp" | "org" | "asn_name" | "organization")
}

fn is_comment_field(key: &str) -> bool {
    matches!(key, "comment" | "description")
}

fn is_interface_list_field(key: &str) -> bool {
    matches!(
        key,
        "interface" | "in-interface" | "out-interface" | "port_name"
            | "bridge" | "wan_interface"
    )
}

/// Check if a string looks like an IPv4 address (with optional CIDR suffix).
fn looks_like_ip_or_cidr(s: &str) -> bool {
    let ip_part = s.split('/').next().unwrap_or(s);
    let parts: Vec<&str> = ip_part.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

/// Check if a string looks like a MAC address (XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX).
fn looks_like_mac(s: &str) -> bool {
    let parts: Vec<&str> = if s.contains(':') && s.len() == 17 {
        s.split(':').collect()
    } else if s.contains('-') && s.len() == 17 {
        s.split('-').collect()
    } else {
        return false;
    };
    parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && u8::from_str_radix(p, 16).is_ok())
}

fn is_private_ip(octets: &[u8; 4]) -> bool {
    match octets[0] {
        10 => true,
        172 => (16..=31).contains(&octets[1]),
        192 => octets[1] == 168,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_ip_deterministic() {
        let s = DemoSanitizer::new();
        let a = s.sanitize_ip("10.20.25.1");
        let b = s.sanitize_ip("10.20.25.1");
        assert_eq!(a, b, "same input must produce same output");
        assert_ne!(a, "10.20.25.1", "must not return the original IP");
    }

    #[test]
    fn sanitize_ip_maps_to_10_249_preserving_vlan() {
        let s = DemoSanitizer::new();
        // All private IPs → 10.249.VLAN.host
        let result = s.sanitize_ip("10.20.25.7");
        let octets: Vec<&str> = result.split('.').collect();
        assert_eq!(octets[0], "10");
        assert_eq!(octets[1], "249");
        assert_eq!(octets[2], "25", "3rd octet (VLAN) must be preserved");

        // 192.168.99.x → 10.249.99.x
        let result2 = s.sanitize_ip("192.168.99.5");
        let octets2: Vec<&str> = result2.split('.').collect();
        assert_eq!(&octets2[..2], &["10", "249"]);
        assert_eq!(octets2[2], "99", "3rd octet (VLAN) must be preserved");

        // 172.16.10.x → 10.249.10.x
        let result3 = s.sanitize_ip("172.16.10.3");
        let octets3: Vec<&str> = result3.split('.').collect();
        assert_eq!(&octets3[..2], &["10", "249"]);
        assert_eq!(octets3[2], "10");

        // Different hosts in same VLAN get different 4th octets
        let a = s.sanitize_ip("10.20.25.1");
        let b = s.sanitize_ip("10.20.25.2");
        assert_ne!(a, b, "different hosts must map to different IPs");
    }

    #[test]
    fn sanitize_cidr() {
        let s = DemoSanitizer::new();
        let result = s.sanitize_ip_or_cidr("10.20.25.0/24");
        assert!(result.ends_with("/24"));
        let octets: Vec<&str> = result.split('/').next().unwrap().split('.').collect();
        assert_eq!(&octets[..2], &["10", "249"]);
        assert_eq!(octets[2], "25");
    }

    #[test]
    fn sanitize_mac_deterministic() {
        let s = DemoSanitizer::new();
        let a = s.sanitize_mac("AA:BB:CC:DD:EE:FF");
        let b = s.sanitize_mac("AA:BB:CC:DD:EE:FF");
        assert_eq!(a, b);
        assert_ne!(a, "AA:BB:CC:DD:EE:FF");
        assert_eq!(a.len(), 17); // Same format
    }

    #[test]
    fn sanitize_mac_locally_administered() {
        let s = DemoSanitizer::new();
        let result = s.sanitize_mac("AA:BB:CC:DD:EE:FF");
        let first_byte = u8::from_str_radix(&result[..2], 16).unwrap();
        assert_eq!(first_byte & 0x02, 0x02, "locally administered bit must be set");
        assert_eq!(first_byte & 0x01, 0x00, "multicast bit must be clear");
    }

    #[test]
    fn sanitize_public_ip() {
        let s = DemoSanitizer::new();
        let result = s.sanitize_ip("8.8.8.8");
        assert!(
            result.starts_with("198.51.100.") || result.starts_with("203.0.113."),
            "public IPs should map to documentation ranges, got: {result}"
        );
    }

    #[test]
    fn sanitize_loopback_unchanged() {
        let s = DemoSanitizer::new();
        assert_eq!(s.sanitize_ip("127.0.0.1"), "127.0.0.1");
    }

    #[test]
    fn sanitize_hostname() {
        let s = DemoSanitizer::new();
        let result = s.sanitize_hostname("spike.kaziik.xyz");
        assert!(!result.contains("kaziik"));
        assert!(!result.contains("spike"));
    }

    #[test]
    fn looks_like_ip_detection() {
        assert!(looks_like_ip_or_cidr("10.20.25.1"));
        assert!(looks_like_ip_or_cidr("192.168.1.1/24"));
        assert!(!looks_like_ip_or_cidr("hello"));
        assert!(!looks_like_ip_or_cidr("10.20.25.256"));
    }

    #[test]
    fn looks_like_mac_detection() {
        assert!(looks_like_mac("AA:BB:CC:DD:EE:FF"));
        assert!(looks_like_mac("aa:bb:cc:dd:ee:ff"));
        assert!(looks_like_mac("AA-BB-CC-DD-EE-FF"));
        assert!(!looks_like_mac("AABBCCDDEEFF"));
        assert!(!looks_like_mac("not-a-mac-addr"));
    }

    #[test]
    fn sanitize_json_value() {
        let s = DemoSanitizer::new();
        let mut val = serde_json::json!({
            "address": "10.20.25.5",
            "mac-address": "AA:BB:CC:DD:EE:FF",
            "host-name": "my-server",
            "interface": "ether1",
            "identity": "RB4011",
            "nested": {
                "src_address": "192.168.1.100",
            }
        });
        s.sanitize_value(&mut val);

        let obj = val.as_object().unwrap();
        assert_ne!(obj["address"].as_str().unwrap(), "10.20.25.5");
        assert_ne!(obj["mac-address"].as_str().unwrap(), "AA:BB:CC:DD:EE:FF");
        assert_ne!(obj["host-name"].as_str().unwrap(), "my-server");
        assert_eq!(obj["interface"].as_str().unwrap(), "ether1", "interfaces should be kept");
        assert_eq!(obj["identity"].as_str().unwrap(), "Demo-Router");

        let nested = obj["nested"].as_object().unwrap();
        assert_ne!(nested["src_address"].as_str().unwrap(), "192.168.1.100");
    }
}
