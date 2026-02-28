//! MAC OUI (manufacturer) lookup from the IEEE OUI database.
//!
//! Parses the bundled `oui.csv` into an in-memory HashMap keyed by the first 3
//! octets of the MAC address (uppercased, colon-separated, e.g. "BC:24:11").

use std::collections::HashMap;
use std::sync::Arc;

/// Bundled IEEE OUI database (downloaded from standards-oui.ieee.org).
const OUI_CSV: &str = include_str!("../../../data/oui.csv");

/// In-memory OUI lookup database.
#[derive(Clone)]
pub struct OuiDb {
    map: HashMap<String, String>,
}

impl OuiDb {
    /// Parse the bundled OUI CSV into an in-memory lookup table.
    pub fn load() -> Arc<Self> {
        let mut map = HashMap::with_capacity(40_000);

        for line in OUI_CSV.lines().skip(1) {
            // CSV format: Registry,Assignment,Organization Name,Organization Address
            // Assignment is hyphen-separated like "286FB9" (6 hex chars)
            let mut fields = CsvFieldIter::new(line);
            let _registry = fields.next(); // MA-L, MA-M, MA-S
            let assignment = match fields.next() {
                Some(a) => a,
                None => continue,
            };
            let org_name = match fields.next() {
                Some(n) => n,
                None => continue,
            };

            if assignment.len() != 6 {
                continue;
            }

            // Convert "286FB9" → "28:6F:B9"
            let key = format!(
                "{}:{}:{}",
                &assignment[0..2],
                &assignment[2..4],
                &assignment[4..6],
            )
            .to_uppercase();

            map.insert(key, org_name.to_string());
        }

        tracing::info!("OUI database loaded: {} entries", map.len());
        Arc::new(Self { map })
    }

    /// Infer a device type and confidence from a manufacturer name.
    ///
    /// Returns `(device_type, confidence)` if a pattern matches.
    /// OUI-based inference uses confidence 0.6 since manufacturer alone is
    /// suggestive but not definitive (e.g. "Samsung" could be phone, TV, or fridge).
    pub fn device_type_from_manufacturer(manufacturer: &str) -> Option<(&'static str, f64)> {
        let lower = manufacturer.to_lowercase();

        // Camera / surveillance
        if matches_any(&lower, &[
            "hikvision", "dahua", "axis communications", "amcrest", "reolink",
            "foscam", "vivotek", "hanwha", "wisenet", "lorex",
        ]) {
            return Some(("camera", 0.6));
        }

        // Network equipment (routers, switches, APs)
        if matches_any(&lower, &[
            "cisco", "juniper", "arista", "mikrotik", "routerboard", "ubiquiti",
            "netgear", "tp-link", "aruba", "ruckus", "fortinet", "meraki",
            "palo alto", "sonicwall", "zyxel", "draytek", "peplink",
        ]) {
            return Some(("network_equipment", 0.6));
        }

        // Printers
        if matches_any(&lower, &[
            "hewlett packard", "hp inc", "canon", "epson", "brother",
            "xerox", "lexmark", "ricoh", "konica minolta", "kyocera",
        ]) {
            return Some(("printer", 0.6));
        }

        // Smart home / IoT hubs
        if matches_any(&lower, &[
            "nest", "ecobee", "rachio", "ring", "wyze", "tuya",
            "shelly", "sonoff", "espressif", "smart home",
            "philips lighting", "signify", "lutron", "aeotec",
        ]) {
            return Some(("smart_home", 0.6));
        }

        // Media / streaming devices
        if matches_any(&lower, &[
            "roku", "amazon technologies", "apple, inc", "google",
            "sonos", "bose", "chromecast", "fire tv",
        ]) {
            return Some(("media_player", 0.5)); // Lower confidence — Apple/Google/Amazon make many things
        }

        // Mobile phones
        if matches_any(&lower, &[
            "samsung electro", "oneplus", "xiaomi", "oppo", "vivo mobile",
            "huawei", "motorola", "nokia", "zte",
        ]) {
            return Some(("phone", 0.5)); // Samsung makes TVs too, so lower confidence
        }

        // Computers / workstations
        if matches_any(&lower, &[
            "dell", "lenovo", "asustek", "asus", "acer", "msi",
            "intel corporate", "gigabyte", "supermicro", "hewlett-packard",
        ]) {
            return Some(("computer", 0.5));
        }

        // Gaming
        if matches_any(&lower, &[
            "nintendo", "sony interactive", "valve", "steam",
        ]) {
            return Some(("gaming", 0.6));
        }

        // NAS / storage
        if matches_any(&lower, &["synology", "qnap", "western digital", "buffalo"]) {
            return Some(("storage", 0.6));
        }

        // Servers / hypervisors
        if matches_any(&lower, &["vmware", "proxmox"]) {
            return Some(("server", 0.6));
        }

        None
    }

    /// Look up the manufacturer for a MAC address.
    /// Accepts formats like "BC:24:11:9C:99:D5" or "bc:24:11:9c:99:d5".
    pub fn lookup(&self, mac: &str) -> Option<&str> {
        // Take first 3 octets, uppercase
        let prefix = mac
            .split(':')
            .take(3)
            .collect::<Vec<_>>()
            .join(":")
            .to_uppercase();

        if prefix.len() != 8 {
            return None;
        }

        self.map.get(&prefix).map(|s| s.as_str())
    }
}

/// Check if a lowercased string contains any of the given patterns.
fn matches_any(haystack: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| haystack.contains(p))
}

/// Simple CSV field iterator that handles quoted fields.
struct CsvFieldIter<'a> {
    remaining: &'a str,
}

impl<'a> CsvFieldIter<'a> {
    fn new(line: &'a str) -> Self {
        Self { remaining: line }
    }

    fn next(&mut self) -> Option<&'a str> {
        if self.remaining.is_empty() {
            return None;
        }

        if self.remaining.starts_with('"') {
            // Quoted field — find closing quote
            let rest = &self.remaining[1..];
            if let Some(end) = rest.find('"') {
                let field = &rest[..end];
                // Skip past closing quote and comma
                self.remaining = if rest.len() > end + 1 {
                    &rest[end + 2..] // skip `",`
                } else {
                    ""
                };
                Some(field)
            } else {
                let field = rest;
                self.remaining = "";
                Some(field)
            }
        } else {
            // Unquoted field
            if let Some(comma) = self.remaining.find(',') {
                let field = &self.remaining[..comma];
                self.remaining = &self.remaining[comma + 1..];
                Some(field)
            } else {
                let field = self.remaining;
                self.remaining = "";
                Some(field)
            }
        }
    }
}
