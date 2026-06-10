#![no_main]
//! Fuzz the RouterOS system-log parser. `message` / `topics` come straight
//! from `/log` on the router and are parsed for firewall fields, prefixes,
//! IPs, ports and MACs (`parse_log_entry` -> `parse_firewall_message`).
//!
//! Geo + OUI lookups are cache-only here: GeoCache is opened against a fresh
//! temp SQLite DB with no MaxMind dir, OuiDb is the embedded table — so no
//! network or filesystem fetch happens inside the fuzz loop.
use ion_drift_web::geo::GeoCache;
use ion_drift_web::log_parser::parse_log_entry;
use ion_drift_web::oui::OuiDb;
use libfuzzer_sys::fuzz_target;
use mikrotik_core::resources::log::LogEntry;
use std::sync::{Arc, OnceLock};

static GEO: OnceLock<GeoCache> = OnceLock::new();
static OUI: OnceLock<Arc<OuiDb>> = OnceLock::new();

fn geo() -> &'static GeoCache {
    GEO.get_or_init(|| {
        let mut path = std::env::temp_dir();
        path.push(format!("ion_drift_fuzz_geo_{}.sqlite", std::process::id()));
        GeoCache::new(&path, None, Vec::new()).expect("geo cache init")
    })
}

fn oui() -> &'static Arc<OuiDb> {
    OUI.get_or_init(OuiDb::load)
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // Use one input bit to cover both the firewall and the generic prefix path.
    let topics = if data[0] & 1 == 0 {
        "firewall"
    } else {
        "system,info,account"
    };
    let message = String::from_utf8_lossy(&data[1..]).into_owned();
    let entry = LogEntry {
        id: String::from("*1"),
        time: String::from("jan/01 00:00:00"),
        topics: Some(topics.to_string()),
        message,
    };
    let _ = parse_log_entry(&entry, geo(), oui());
});
