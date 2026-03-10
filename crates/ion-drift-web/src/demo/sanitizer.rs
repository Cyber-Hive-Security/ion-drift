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
    /// VLAN ID remapping: real VLAN ID → fake VLAN ID (10, 12, 14, ...).
    vlan_id_cache: Mutex<HashMap<u16, u16>>,
    /// Next fake VLAN ID to assign.
    next_vlan_id: Mutex<u16>,
}

impl DemoSanitizer {
    pub fn new() -> Self {
        Self {
            seed: *b"ion-drift-demo!1",
            ip_cache: Mutex::new(HashMap::new()),
            mac_cache: Mutex::new(HashMap::new()),
            hostname_cache: Mutex::new(HashMap::new()),
            hostname_counter: Mutex::new(0),
            vlan_id_cache: Mutex::new(HashMap::new()),
            next_vlan_id: Mutex::new(10),
        }
    }

    /// Map a real VLAN ID to a fake one (10, 12, 14, ...).
    fn remap_vlan_id(&self, real_id: u16) -> u16 {
        let mut cache = self.vlan_id_cache.lock().unwrap();
        if let Some(&fake) = cache.get(&real_id) {
            return fake;
        }
        let mut next = self.next_vlan_id.lock().unwrap();
        let fake = *next;
        *next += 2;
        cache.insert(real_id, fake);
        fake
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
                } else if is_vlan_name_field(key_lower) {
                    *s = self.sanitize_vlan_name(s);
                } else if is_interface_list_field(key_lower) || key_lower == "name" {
                    // Keep interface names like "ether1", "bridge1" — they're generic
                    // But sanitize VLAN interface names that embed real VLAN descriptions
                    // e.g. "vlan25-Trusted-Services" → "vlan25"
                    if looks_like_vlan_interface(s) {
                        *s = self.sanitize_vlan_interface_name(s);
                    }
                } else {
                    // For unknown fields, check if the value looks like an IP or MAC
                    *s = self.sanitize_string(s);
                }
            }
            serde_json::Value::Number(n) => {
                // Remap numeric VLAN ID fields
                if is_vlan_id_field(key_lower) {
                    if let Some(id) = n.as_u64() {
                        let fake = self.remap_vlan_id(id as u16);
                        *value = serde_json::Value::Number(serde_json::Number::from(fake));
                    }
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
            // 3rd octet (VLAN ID) is remapped to fake sequence (10, 12, 14, ...)
            let fake_vlan = self.remap_vlan_id(octets[2] as u16) as u8;
            let o4 = (hash[0] as u16 % 254 + 1) as u8;
            Ipv4Addr::new(10, 249, fake_vlan, o4)
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

    /// Replace real VLAN names/IDs with remapped values.
    /// Pure numeric IDs get remapped (25 → 10). Names get "VLAN <remapped>".
    fn sanitize_vlan_name(&self, name: &str) -> String {
        if name.is_empty() || name == "WAN" || name == "unknown" {
            return name.to_string();
        }
        // Pure number (VLAN ID) → remap
        if let Ok(id) = name.parse::<u16>() {
            return self.remap_vlan_id(id).to_string();
        }
        // Real name like "Trusted Services" → "VLAN <remapped>"
        let hash = self.hash_bytes(name.as_bytes());
        let pseudo_id = (hash[0] as u16 % 200) + 100;
        let fake_id = self.remap_vlan_id(pseudo_id);
        format!("VLAN {fake_id}")
    }

    /// Strip descriptive suffix from VLAN interface name and remap the ID.
    /// "vlan25-Trusted-Services" → "vlan10"
    fn sanitize_vlan_interface_name(&self, s: &str) -> String {
        let after_prefix = &s[4..];
        let digit_end = after_prefix
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(after_prefix.len());
        let real_id: u16 = after_prefix[..digit_end].parse().unwrap_or(0);
        let fake_id = self.remap_vlan_id(real_id);
        format!("vlan{fake_id}")
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

fn is_vlan_name_field(key: &str) -> bool {
    matches!(
        key,
        "src_vlan" | "dst_vlan" | "vlan_name" | "vlan"
            | "current_vlan"
    )
}

fn is_vlan_id_field(key: &str) -> bool {
    matches!(key, "vlan_id" | "vlanid" | "vid")
}

fn is_interface_list_field(key: &str) -> bool {
    matches!(
        key,
        "interface" | "in-interface" | "out-interface" | "port_name"
            | "bridge" | "wan_interface"
    )
}

/// Check if a string looks like a VLAN interface name (e.g. "vlan25-Trusted-Services").
fn looks_like_vlan_interface(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.starts_with("vlan") && s.len() > 4 && s[4..].starts_with(|c: char| c.is_ascii_digit())
}

// sanitize_vlan_interface_name is a method on DemoSanitizer (uses remap_vlan_id)

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
    fn sanitize_ip_maps_to_10_249_with_remapped_vlan() {
        let s = DemoSanitizer::new();
        // All private IPs → 10.249.<remapped_vlan>.host
        let result = s.sanitize_ip("10.20.25.7");
        let octets: Vec<&str> = result.split('.').collect();
        assert_eq!(octets[0], "10");
        assert_eq!(octets[1], "249");
        // 3rd octet is remapped (first VLAN seen gets 10)
        let vlan25_remapped: u16 = octets[2].parse().unwrap();
        assert_eq!(vlan25_remapped, 10, "first VLAN seen should remap to 10");

        // Second unique VLAN gets 12
        let result2 = s.sanitize_ip("192.168.99.5");
        let octets2: Vec<&str> = result2.split('.').collect();
        assert_eq!(&octets2[..2], &["10", "249"]);
        let vlan99_remapped: u16 = octets2[2].parse().unwrap();
        assert_eq!(vlan99_remapped, 12, "second VLAN seen should remap to 12");

        // Same VLAN (25) gets same remapped ID
        let result3 = s.sanitize_ip("10.20.25.100");
        let octets3: Vec<&str> = result3.split('.').collect();
        assert_eq!(octets3[2], "10", "same VLAN must get same remapped ID");

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
        // 3rd octet is remapped, not the original
        let remapped: u16 = octets[2].parse().unwrap();
        assert!(remapped >= 10 && remapped % 2 == 0, "VLAN ID should be remapped to even number >= 10");
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

    #[test]
    fn sanitize_vlan_names() {
        let s = DemoSanitizer::new();
        // src_vlan/dst_vlan fields: real names → "VLAN xx"
        let result = s.sanitize_vlan_name("Trusted Services");
        assert!(result.starts_with("VLAN "), "got: {result}");
        assert_ne!(result, "Trusted Services");
        // Special values preserved
        assert_eq!(s.sanitize_vlan_name("WAN"), "WAN");
        assert_eq!(s.sanitize_vlan_name("unknown"), "unknown");
        // Numeric VLAN IDs get remapped
        let remapped = s.sanitize_vlan_name("25");
        assert_ne!(remapped, "25");
        let id: u16 = remapped.parse().unwrap();
        assert!(id >= 10 && id % 2 == 0, "remapped VLAN ID should be even >= 10, got {id}");
    }

    #[test]
    fn sanitize_vlan_interface_names() {
        let s = DemoSanitizer::new();
        // "vlan25-Trusted-Services" → "vlan<remapped>"
        let result = s.sanitize_vlan_interface_name("vlan25-Trusted-Services");
        assert!(result.starts_with("vlan"), "got: {result}");
        assert!(!result.contains("Trusted"));
        // Second VLAN gets different ID
        let result2 = s.sanitize_vlan_interface_name("vlan99-IoT-No-Internet");
        assert_ne!(result, result2);
        // Same VLAN gets same result
        let result3 = s.sanitize_vlan_interface_name("vlan25-Something-Else");
        assert_eq!(result, result3, "same VLAN ID must remap consistently");
        // Detection
        assert!(looks_like_vlan_interface("vlan25-Trusted-Services"));
        assert!(!looks_like_vlan_interface("ether1"));
        assert!(!looks_like_vlan_interface("bridge1"));
    }
}
