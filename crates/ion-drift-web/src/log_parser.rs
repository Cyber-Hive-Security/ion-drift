//! MikroTik log message parser.
//!
//! Extracts structured fields from raw RouterOS log messages based on their
//! topic and prefix. The main firewall log format is:
//!
//! ```text
//! PREFIX direction: in:IFACE out:IFACE, connection-state:STATE src-mac MAC,
//!   proto PROTO, SRC_IP:SRC_PORT->DST_IP:DST_PORT, len LEN
//! ```
//!
//! ICMP variant (no ports):
//!
//! ```text
//! PREFIX direction: in:IFACE out:IFACE, connection-state:STATE src-mac MAC,
//!   proto ICMP (type T, code C), SRC_IP->DST_IP, len LEN
//! ```

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::geo::{GeoCache, GeoInfo};
use crate::oui::OuiDb;

/// Structured fields extracted from a log message.
#[derive(Debug, Clone, Serialize)]
pub struct ParsedFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_country: Option<GeoInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_country: Option<GeoInfo>,
    pub src_flagged: bool,
    pub dst_flagged: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
}

/// A fully structured log entry ready for the frontend.
#[derive(Debug, Clone, Serialize)]
pub struct StructuredLogEntry {
    pub id: String,
    pub timestamp: String,
    pub topics: Vec<String>,
    pub level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parsed: Option<ParsedFields>,
    /// Raw messages from non-terminating log rules that matched the same packet.
    /// Empty for normal entries; populated by [`deduplicate_log_pairs`].
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub paired_messages: Vec<String>,
}

/// Aggregated analytics over a set of log entries.
#[derive(Debug, Clone, Serialize)]
pub struct LogAnalytics {
    pub total: usize,
    pub by_severity: HashMap<String, usize>,
    pub by_action: HashMap<String, usize>,
    pub by_topic: HashMap<String, usize>,
    pub top_dropped_sources: Vec<IpCount>,
    pub top_targeted_ports: Vec<PortCount>,
    pub drops_per_interface: Vec<InterfaceCount>,
    pub volume_over_time: Vec<TimeCount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpCount {
    pub ip: String,
    pub count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<GeoInfo>,
    pub flagged: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortCount {
    pub port: u16,
    pub count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceCount {
    pub interface: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimeCount {
    pub minute: String,
    pub count: usize,
}

/// Full response from the structured logs endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct LogsResponse {
    pub entries: Vec<StructuredLogEntry>,
    pub analytics: LogAnalytics,
}

// ── Parsing ──────────────────────────────────────────────────────

/// Derive severity level from comma-separated topics string.
pub fn derive_level(topics: &str) -> &'static str {
    if topics.contains("critical") {
        "critical"
    } else if topics.contains("error") {
        "error"
    } else if topics.contains("warning") {
        "warning"
    } else {
        "info"
    }
}

/// Derive action from a log prefix (e.g. "DROP-INPUT" → "drop").
fn derive_action(prefix: &str) -> Option<String> {
    let upper = prefix.to_uppercase();
    if upper.starts_with("DROP") {
        Some("drop".into())
    } else if upper.starts_with("ACCEPT") {
        Some("accept".into())
    } else if upper.starts_with("REJECT") {
        Some("reject".into())
    } else {
        None
    }
}

/// Extract the log prefix from a firewall message.
/// Prefix is everything before the first space followed by a direction keyword.
fn extract_prefix(msg: &str) -> Option<&str> {
    // Format: "PREFIX direction: ..."
    // PREFIX can contain hyphens. Direction is "input:", "forward:", or "output:"
    let first_space = msg.find(' ')?;
    let rest = &msg[first_space + 1..];
    if rest.starts_with("input:")
        || rest.starts_with("forward:")
        || rest.starts_with("output:")
    {
        Some(&msg[..first_space])
    } else {
        None
    }
}

/// Parse a firewall log message into structured fields.
fn parse_firewall_message(msg: &str, geo_cache: &GeoCache, oui_db: &OuiDb) -> Option<ParsedFields> {
    let prefix = extract_prefix(msg)?;
    let action = derive_action(prefix);

    // After the prefix and space: "direction: in:IFACE out:IFACE, ..."
    let after_prefix = &msg[prefix.len() + 1..];

    // Extract direction (input/forward/output)
    let direction = if after_prefix.starts_with("input:") {
        Some("input".to_string())
    } else if after_prefix.starts_with("forward:") {
        Some("forward".to_string())
    } else if after_prefix.starts_with("output:") {
        Some("output".to_string())
    } else {
        None
    };

    // Extract in-interface: find "in:" then take until space
    let in_interface = extract_field(after_prefix, "in:");
    // Extract out-interface: find "out:" then take until comma
    let out_interface = extract_field(after_prefix, "out:")
        .filter(|s| s != "(unknown 0)");

    // Extract src-mac
    let mac = extract_field(after_prefix, "src-mac ");

    // Extract protocol: "proto " then take until comma or end
    let protocol = extract_proto(after_prefix);

    // Extract src/dst IP and ports from the address pattern
    let (src_ip, src_port, dst_ip, dst_port) = extract_addresses(after_prefix);

    // Extract length
    let length = extract_field(after_prefix, "len ")
        .and_then(|s| s.parse::<u32>().ok());

    // Geo enrichment (cache-only — no HTTP calls in sync context)
    let src_country = src_ip.as_deref().and_then(|ip| geo_cache.lookup_cached(ip));
    let dst_country = dst_ip.as_deref().and_then(|ip| geo_cache.lookup_cached(ip));
    let src_flagged = src_country
        .as_ref()
        .map(|c| geo_cache.is_flagged(&c.country_code))
        .unwrap_or(false);
    let dst_flagged = dst_country
        .as_ref()
        .map(|c| geo_cache.is_flagged(&c.country_code))
        .unwrap_or(false);

    // OUI lookup
    let manufacturer = mac.as_deref().and_then(|m| oui_db.lookup(m).map(String::from));

    Some(ParsedFields {
        direction,
        in_interface,
        out_interface,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        action,
        mac,
        length,
        src_country,
        dst_country,
        src_flagged,
        dst_flagged,
        manufacturer,
    })
}

/// Extract a simple field value: find `key` in `text`, return chars until delimiter.
fn extract_field(text: &str, key: &str) -> Option<String> {
    let start = text.find(key)? + key.len();
    let rest = &text[start..];
    let end = rest
        .find(|c: char| c == ',' || c == ' ' || c == '\n')
        .unwrap_or(rest.len());
    let val = rest[..end].trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

/// Extract protocol string, handling "TCP (SYN)" and "ICMP (type N, code N)".
fn extract_proto(text: &str) -> Option<String> {
    let start = text.find("proto ")? + 6;
    let rest = &text[start..];
    // If it starts with a word followed by " (", include the parenthetical
    let word_end = rest.find(|c: char| c == ',' || c == ' ').unwrap_or(rest.len());
    let word = &rest[..word_end];

    // Check if there's a parenthetical like "(SYN)" or "(type 8, code 0)"
    if rest.len() > word_end && rest[word_end..].starts_with(' ') {
        let after_word = &rest[word_end + 1..];
        if after_word.starts_with('(') {
            if let Some(paren_end) = after_word.find(')') {
                return Some(format!("{} {}", word, &after_word[..=paren_end]));
            }
        }
    }

    Some(word.to_string())
}

/// Extract src/dst IP addresses and optional ports from the address pattern.
/// Handles: "SRC_IP:SRC_PORT->DST_IP:DST_PORT" and "SRC_IP->DST_IP" (ICMP).
fn extract_addresses(text: &str) -> (Option<String>, Option<u16>, Option<String>, Option<u16>) {
    // Find the arrow "->" which separates src and dst
    // The address section comes after "proto ..., " — find the last "proto " context
    let proto_pos = match text.rfind("proto ") {
        Some(p) => p,
        None => return (None, None, None, None),
    };

    // Skip past "proto WORD (...)," to the address part
    let after_proto = &text[proto_pos..];
    let comma_pos = match after_proto.find(", ") {
        Some(p) => proto_pos + p + 2,
        None => return (None, None, None, None),
    };

    let addr_section = &text[comma_pos..];
    // addr_section is like "10.20.25.15:54329->10.20.25.255:32414, len 49"
    // or "10.20.30.88->10.20.30.1, len 84" (ICMP)

    let arrow = match addr_section.find("->") {
        Some(p) => p,
        None => return (None, None, None, None),
    };

    let src_part = &addr_section[..arrow];
    let dst_rest = &addr_section[arrow + 2..];
    // dst_rest ends at ", " or end of string
    let dst_end = dst_rest
        .find(", ")
        .unwrap_or(dst_rest.len());
    let dst_part = &dst_rest[..dst_end];

    let (src_ip, src_port) = split_ip_port(src_part);
    let (dst_ip, dst_port) = split_ip_port(dst_part);

    (src_ip, src_port, dst_ip, dst_port)
}

/// Split "IP:PORT" or just "IP" into components.
fn split_ip_port(s: &str) -> (Option<String>, Option<u16>) {
    // IPv4 with port: "1.2.3.4:5678"
    // IPv4 without port: "1.2.3.4"
    if let Some(last_colon) = s.rfind(':') {
        let maybe_port = &s[last_colon + 1..];
        if let Ok(port) = maybe_port.parse::<u16>() {
            let ip = &s[..last_colon];
            return (Some(ip.to_string()), Some(port));
        }
    }
    if s.is_empty() {
        (None, None)
    } else {
        (Some(s.to_string()), None)
    }
}

// ── Public API ───────────────────────────────────────────────────

/// Parse a raw RouterOS LogEntry into a StructuredLogEntry.
pub fn parse_log_entry(
    entry: &mikrotik_core::resources::log::LogEntry,
    geo_cache: &GeoCache,
    oui_db: &OuiDb,
) -> StructuredLogEntry {
    let topics_str = entry.topics.as_deref().unwrap_or("");
    let topics: Vec<String> = topics_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let level = derive_level(topics_str).to_string();

    let is_firewall = topics.iter().any(|t| t == "firewall");
    let prefix = if is_firewall {
        extract_prefix(&entry.message).map(String::from)
    } else {
        // Check for prefixed non-firewall messages like "ACCESS: ..."
        if let Some(colon_pos) = entry.message.find(": ") {
            let candidate = &entry.message[..colon_pos];
            if candidate.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && candidate.len() <= 20
            {
                Some(candidate.to_string())
            } else {
                None
            }
        } else {
            None
        }
    };

    let parsed = if is_firewall {
        parse_firewall_message(&entry.message, geo_cache, oui_db)
    } else {
        None
    };

    StructuredLogEntry {
        id: entry.id.clone(),
        timestamp: entry.time.clone(),
        topics,
        level,
        prefix,
        message: entry.message.clone(),
        parsed,
        paired_messages: Vec::new(),
    }
}

/// Deduplicate log entries where the same packet triggered both a non-terminating
/// log rule and a terminating drop/accept rule.
///
/// Detection: entries with matching timestamp (same second), protocol, source,
/// destination, interfaces, and packet length — but different prefixes — where
/// exactly one entry has a terminating action (`drop`/`accept`/`reject`).
///
/// The terminating entry is kept with the non-terminating message(s) stored in
/// `paired_messages` for display in the expanded detail view.
pub fn deduplicate_log_pairs(entries: Vec<StructuredLogEntry>) -> Vec<StructuredLogEntry> {
    /// Build a dedup key from packet-identifying fields.
    /// Returns None for non-firewall entries (no parsed fields / no protocol).
    fn dedup_key(entry: &StructuredLogEntry) -> Option<String> {
        let p = entry.parsed.as_ref()?;
        let proto = p.protocol.as_deref()?;

        // Truncate timestamp to the second (first 19 chars of "YYYY-MM-DD HH:MM:SS")
        let ts = if entry.timestamp.len() >= 19 {
            &entry.timestamp[..19]
        } else {
            &entry.timestamp
        };

        let src_ip = p.src_ip.as_deref().unwrap_or("");
        let dst_ip = p.dst_ip.as_deref().unwrap_or("");
        let src_port = p.src_port.map(|v| v.to_string()).unwrap_or_default();
        let dst_port = p.dst_port.map(|v| v.to_string()).unwrap_or_default();
        let in_iface = p.in_interface.as_deref().unwrap_or("");
        let out_iface = p.out_interface.as_deref().unwrap_or("");
        let length = p.length.map(|v| v.to_string()).unwrap_or_default();

        Some(format!(
            "{ts}|{proto}|{src_ip}:{src_port}|{dst_ip}:{dst_port}|{in_iface}|{out_iface}|{length}"
        ))
    }

    fn is_terminating(entry: &StructuredLogEntry) -> bool {
        entry
            .parsed
            .as_ref()
            .and_then(|p| p.action.as_deref())
            .is_some_and(|a| matches!(a, "drop" | "accept" | "reject"))
    }

    // Group entry indices by their dedup key
    let mut key_groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, entry) in entries.iter().enumerate() {
        if let Some(key) = dedup_key(entry) {
            key_groups.entry(key).or_default().push(i);
        }
    }

    // Determine merges: primary_idx → vec of secondary messages
    let mut merges: HashMap<usize, Vec<String>> = HashMap::new();
    let mut remove: HashSet<usize> = HashSet::new();

    for indices in key_groups.values() {
        if indices.len() < 2 {
            continue;
        }

        // All entries in the group must have different prefixes (same prefix = same rule,
        // likely different packets that happen to look identical).
        let prefixes: HashSet<Option<&str>> = indices
            .iter()
            .map(|&i| entries[i].prefix.as_deref())
            .collect();
        if prefixes.len() < 2 {
            continue;
        }

        // Partition into terminating vs non-terminating
        let mut terminating: Vec<usize> = Vec::new();
        let mut non_terminating: Vec<usize> = Vec::new();
        for &i in indices {
            if is_terminating(&entries[i]) {
                terminating.push(i);
            } else {
                non_terminating.push(i);
            }
        }

        // Only collapse when exactly 1 terminating and 1+ non-terminating.
        // Multiple terminating entries = genuinely different packets.
        if terminating.len() != 1 || non_terminating.is_empty() {
            continue;
        }

        let primary = terminating[0];
        let secondary_msgs: Vec<String> = non_terminating
            .iter()
            .map(|&i| entries[i].message.clone())
            .collect();

        merges.insert(primary, secondary_msgs);
        for &i in &non_terminating {
            remove.insert(i);
        }
    }

    // Build result, applying merges and skipping removed entries
    let mut result = Vec::with_capacity(entries.len() - remove.len());
    for (i, mut entry) in entries.into_iter().enumerate() {
        if remove.contains(&i) {
            continue;
        }
        if let Some(msgs) = merges.remove(&i) {
            entry.paired_messages = msgs;
        }
        result.push(entry);
    }

    result
}

/// Compute analytics over a slice of structured log entries.
pub fn compute_analytics(entries: &[StructuredLogEntry]) -> LogAnalytics {
    let total = entries.len();

    let mut by_severity: HashMap<String, usize> = HashMap::new();
    let mut by_action: HashMap<String, usize> = HashMap::new();
    let mut by_topic: HashMap<String, usize> = HashMap::new();
    let mut dropped_sources: HashMap<String, (usize, Option<GeoInfo>, bool)> = HashMap::new();
    let mut targeted_ports: HashMap<(u16, String), usize> = HashMap::new();
    let mut drops_by_iface: HashMap<String, usize> = HashMap::new();
    let mut volume_by_minute: HashMap<String, usize> = HashMap::new();

    for entry in entries {
        // Severity
        *by_severity.entry(entry.level.clone()).or_default() += 1;

        // Topics (deduplicated per entry)
        for topic in &entry.topics {
            // Normalize: use the primary topic (firewall, dhcp, interface, system, wireguard, dns)
            let primary = match topic.as_str() {
                "info" | "warning" | "error" | "critical" | "account" => continue,
                other => other,
            };
            *by_topic.entry(primary.to_string()).or_default() += 1;
        }

        // Action
        if let Some(ref parsed) = entry.parsed {
            if let Some(ref action) = parsed.action {
                *by_action.entry(action.clone()).or_default() += 1;

                // Drops analytics
                if action == "drop" {
                    if let Some(ref src_ip) = parsed.src_ip {
                        let e = dropped_sources
                            .entry(src_ip.clone())
                            .or_insert((0, None, false));
                        e.0 += 1;
                        if e.1.is_none() {
                            e.1.clone_from(&parsed.src_country);
                        }
                        if parsed.src_flagged {
                            e.2 = true;
                        }
                    }
                    if let Some(port) = parsed.dst_port {
                        let proto = parsed
                            .protocol
                            .as_deref()
                            .unwrap_or("?")
                            .split_whitespace()
                            .next()
                            .unwrap_or("?")
                            .to_string();
                        *targeted_ports.entry((port, proto)).or_default() += 1;
                    }
                    if let Some(ref iface) = parsed.in_interface {
                        *drops_by_iface.entry(iface.clone()).or_default() += 1;
                    }
                }
            }
        }

        // Volume over time (group by minute)
        // Timestamps look like "2026-02-20 14:30:45"
        let minute = if entry.timestamp.len() >= 16 {
            &entry.timestamp[..16]
        } else {
            &entry.timestamp
        };
        *volume_by_minute.entry(minute.to_string()).or_default() += 1;
    }

    // Sort and take top N
    let mut top_dropped_sources: Vec<IpCount> = dropped_sources
        .into_iter()
        .map(|(ip, (count, country, flagged))| IpCount {
            ip,
            count,
            country,
            flagged,
        })
        .collect();
    top_dropped_sources.sort_by(|a, b| b.count.cmp(&a.count));
    top_dropped_sources.truncate(10);

    let mut top_targeted_ports: Vec<PortCount> = targeted_ports
        .into_iter()
        .map(|((port, protocol), count)| PortCount {
            port,
            count,
            protocol: Some(protocol),
        })
        .collect();
    top_targeted_ports.sort_by(|a, b| b.count.cmp(&a.count));
    top_targeted_ports.truncate(10);

    let mut drops_per_interface: Vec<InterfaceCount> = drops_by_iface
        .into_iter()
        .map(|(interface, count)| InterfaceCount { interface, count })
        .collect();
    drops_per_interface.sort_by(|a, b| b.count.cmp(&a.count));

    let mut volume_over_time: Vec<TimeCount> = volume_by_minute
        .into_iter()
        .map(|(minute, count)| TimeCount { minute, count })
        .collect();
    volume_over_time.sort_by(|a, b| a.minute.cmp(&b.minute));

    LogAnalytics {
        total,
        by_severity,
        by_action,
        by_topic,
        top_dropped_sources,
        top_targeted_ports,
        drops_per_interface,
        volume_over_time,
    }
}
