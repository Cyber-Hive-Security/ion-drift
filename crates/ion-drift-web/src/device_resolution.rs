//! Device identity resolution — the single source of truth for mapping
//! LLDP neighbors, MAC addresses, and IP addresses to known devices.
//!
//! Consumed by: correlation engine, topology inference, topology builder,
//! and eventually Arc and alerting.
//!
//! # Resolution precedence (within `resolve_neighbor`)
//!
//! 1. Exact identity match (confidence 0.95)
//! 2. RouterOS health-check identity (confidence 0.90)
//! 3. Normalized/fuzzy identity (confidence 0.75)
//! 4. IP address, skip fe80:: link-local (confidence 0.80)
//! 5. MAC address fallback (confidence 0.60)
//! 6. Learned mapping, if not expired and above confidence floor (confidence varies)
//!
//! Confidence values are **ordinal heuristics**, not calibrated probabilities.
//! They support ranking and gating decisions, not statistical inference.

use std::collections::HashMap;
use std::time::Duration;

use ion_drift_storage::switch::NeighborEntry;

use crate::device_manager::{DeviceEntry, DeviceManager, DeviceStatus};
use crate::infrastructure_snapshot::{EvidenceAuthority, ResolutionMethod};

// ── Constants ───────────────────────────────────────────────────

/// Minimum confidence required for a resolution to be learned.
/// MAC-only matches (0.60) are never learned.
const LEARNING_CONFIDENCE_FLOOR: f32 = 0.70;

/// Maximum learned mappings to prevent unbounded growth.
const MAX_LEARNED_MAPPINGS: usize = 500;

/// Default TTL for learned mappings (24 hours).
pub const DEFAULT_LEARNING_TTL: Duration = Duration::from_secs(24 * 3600);

// ── Public types ────────────────────────────────────────────────

/// Result of resolving a single LLDP neighbor to a known device.
#[derive(Debug, Clone)]
pub struct ResolvedNeighborMatch {
    pub device_id: String,
    pub method: ResolutionMethod,
    pub authority: EvidenceAuthority,
    pub confidence: f32,
}

/// A learned mapping with metadata for TTL, audit, and link-down invalidation.
#[derive(Debug, Clone)]
pub struct LearnedMapping {
    pub device_id: String,
    pub original_method: ResolutionMethod,
    pub learned_at_secs: i64,
    /// Which device reported this neighbor (for audit trail).
    pub source_device: String,
    /// Which port the neighbor was seen on (for link-down invalidation).
    pub source_port: Option<String>,
    pub confidence: f32,
}

/// Entry returned by the audit endpoint.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LearnedAuditEntry {
    pub key: String,
    pub device_id: String,
    pub original_method: String,
    pub learned_at_secs: i64,
    pub source_device: String,
    pub source_port: Option<String>,
    pub confidence: f32,
    pub age_secs: i64,
}

// ── Resolution maps ─────────────────────────────────────────────

/// All known resolution mappings, built from DeviceManager + accumulated learning.
///
/// This is the single resolver for the entire platform. Do not create
/// parallel resolution logic elsewhere.
pub struct DeviceResolutionMaps {
    /// LLDP identity (exact lowercase) → device_id
    identity_exact: HashMap<String, String>,
    /// Normalized identity (stripped non-alphanum, lowercase) → device_id
    identity_normalized: HashMap<String, String>,
    /// RouterOS health-check identity (exact lowercase) → device_id
    routeros_identity: HashMap<String, String>,
    /// IP address → device_id
    ip_to_device: HashMap<String, String>,
    /// MAC address (uppercase) → device_id
    mac_to_device: HashMap<String, String>,
    /// Learned mappings with metadata for TTL and auditing.
    learned: HashMap<String, LearnedMapping>,
}

impl DeviceResolutionMaps {
    /// Build resolution maps from DeviceManager entries.
    ///
    /// Optionally carries forward prior learned mappings (already TTL-filtered).
    pub fn build(
        device_manager: &DeviceManager,
        prior_learned: Option<HashMap<String, LearnedMapping>>,
    ) -> Self {
        let mut maps = Self {
            identity_exact: HashMap::new(),
            identity_normalized: HashMap::new(),
            routeros_identity: HashMap::new(),
            ip_to_device: HashMap::new(),
            mac_to_device: HashMap::new(),
            learned: prior_learned.unwrap_or_default(),
        };

        for entry in device_manager.all_devices() {
            let id = &entry.record.id;

            // Exact lowercase mappings for name and id
            maps.identity_exact
                .insert(entry.record.name.to_lowercase(), id.clone());
            maps.identity_exact
                .insert(id.to_lowercase(), id.clone());

            // IP mapping
            maps.ip_to_device
                .insert(entry.record.host.clone(), id.clone());

            // Normalized fuzzy keys for name and id
            maps.identity_normalized
                .insert(normalize_identity(&entry.record.name), id.clone());
            maps.identity_normalized
                .insert(normalize_identity(id), id.clone());

            // RouterOS health-check identity (MNDP broadcast string)
            if let DeviceStatus::Online { ref identity } = entry.status {
                maps.routeros_identity
                    .insert(identity.to_lowercase(), id.clone());
                // Also add normalized form
                maps.identity_normalized
                    .insert(normalize_identity(identity), id.clone());
            }
        }

        maps
    }

    /// Build MAC → device mappings from neighbor records.
    ///
    /// Called after initial `build()` with neighbor data from the switch store.
    /// If a neighbor's identity or IP already resolves to a registered device,
    /// record the neighbor's MAC for future fallback matching.
    pub fn populate_mac_from_neighbors(&mut self, neighbors: &[NeighborEntry]) {
        for nb in neighbors {
            if let Some(ref mac) = nb.mac_address {
                // Check if this neighbor resolves via identity or IP
                let resolved = nb
                    .identity
                    .as_deref()
                    .and_then(|id| self.identity_exact.get(&id.to_lowercase()).cloned())
                    .or_else(|| {
                        nb.address
                            .as_deref()
                            .filter(|a| !a.starts_with("fe80"))
                            .and_then(|addr| self.ip_to_device.get(addr).cloned())
                    });

                if let Some(device_id) = resolved {
                    self.mac_to_device
                        .entry(mac.to_uppercase())
                        .or_insert(device_id);
                }
            }
        }
    }

    /// Resolve an LLDP neighbor to a registered device.
    ///
    /// Tries resolution methods in strict precedence order.
    /// CSS/SwOS graceful fallback: if identity resolution fails for a device
    /// previously seen via SNMP sysName, the MAC fallback will still catch it
    /// since CSS devices usually remain reachable via SNMP/MAC even when MNDP
    /// drops out.
    pub fn resolve_neighbor(&self, neighbor: &NeighborEntry) -> Option<ResolvedNeighborMatch> {
        // 1. Exact identity match
        if let Some(device_id) = neighbor
            .identity
            .as_deref()
            .and_then(|id| self.identity_exact.get(&id.to_lowercase()))
        {
            return Some(ResolvedNeighborMatch {
                device_id: device_id.clone(),
                method: ResolutionMethod::ExactIdentity,
                authority: EvidenceAuthority::LldpObserved,
                confidence: 0.95,
            });
        }

        // 2. RouterOS health-check identity
        if let Some(device_id) = neighbor
            .identity
            .as_deref()
            .and_then(|id| self.routeros_identity.get(&id.to_lowercase()))
        {
            return Some(ResolvedNeighborMatch {
                device_id: device_id.clone(),
                method: ResolutionMethod::RouterOsIdentity,
                authority: EvidenceAuthority::LldpObserved,
                confidence: 0.90,
            });
        }

        // 3. Normalized/fuzzy identity match
        if let Some(device_id) = neighbor
            .identity
            .as_deref()
            .and_then(|id| self.identity_normalized.get(&normalize_identity(id)))
        {
            return Some(ResolvedNeighborMatch {
                device_id: device_id.clone(),
                method: ResolutionMethod::NormalizedIdentity,
                authority: EvidenceAuthority::LldpObserved,
                confidence: 0.75,
            });
        }

        // 4. IP address match (skip fe80:: link-local — useless for matching)
        if let Some(device_id) = neighbor
            .address
            .as_deref()
            .filter(|a| !a.starts_with("fe80"))
            .and_then(|addr| self.ip_to_device.get(addr))
        {
            return Some(ResolvedNeighborMatch {
                device_id: device_id.clone(),
                method: ResolutionMethod::IpAddress,
                authority: EvidenceAuthority::LldpObserved,
                confidence: 0.80,
            });
        }

        // 5. MAC address fallback
        if let Some(device_id) = neighbor
            .mac_address
            .as_deref()
            .and_then(|mac| self.mac_to_device.get(&mac.to_uppercase()))
        {
            return Some(ResolvedNeighborMatch {
                device_id: device_id.clone(),
                method: ResolutionMethod::MacFallback,
                authority: EvidenceAuthority::LldpObserved,
                confidence: 0.60,
            });
        }

        // 6. Learned mapping (checked last — registry always outranks)
        let learned_key = self.learned_key_for(neighbor);
        if let Some(mapping) = learned_key.and_then(|k| self.learned.get(&k)) {
            // Don't return learned mapping if a registry mapping exists for the
            // same device_id under a different key — registry is authoritative.
            return Some(ResolvedNeighborMatch {
                device_id: mapping.device_id.clone(),
                method: ResolutionMethod::Learned {
                    original_method: Box::new(mapping.original_method.clone()),
                },
                authority: EvidenceAuthority::LearnedMapping,
                confidence: mapping.confidence * 0.9, // Decay learned confidence slightly
            });
        }

        None
    }

    /// Record a successful resolution for future learning.
    ///
    /// # Guardrails enforced:
    /// 1. Confidence >= LEARNING_CONFIDENCE_FLOOR (0.70) — MAC-only never learned
    /// 2. No cascading — Learned matches cannot produce new learned entries
    /// 3. Source and reason recorded for audit trail
    /// 4. Cardinality capped at MAX_LEARNED_MAPPINGS
    pub fn learn(
        &mut self,
        neighbor: &NeighborEntry,
        result: &ResolvedNeighborMatch,
        now_secs: i64,
    ) {
        // Guard: confidence floor
        if result.confidence < LEARNING_CONFIDENCE_FLOOR {
            return;
        }

        // Guard: no cascading — learned matches cannot produce new learned entries
        if matches!(result.method, ResolutionMethod::Learned { .. }) {
            return;
        }

        // Build a stable key from the neighbor
        let key = match self.learned_key_for(neighbor) {
            Some(k) => k,
            None => return,
        };

        // Don't overwrite if registry already resolves this key
        if self.resolves_via_registry(&key) {
            return;
        }

        // Cap cardinality — evict oldest if at limit
        if self.learned.len() >= MAX_LEARNED_MAPPINGS && !self.learned.contains_key(&key) {
            if let Some(oldest_key) = self
                .learned
                .iter()
                .min_by_key(|(_, v)| v.learned_at_secs)
                .map(|(k, _)| k.clone())
            {
                self.learned.remove(&oldest_key);
            }
        }

        self.learned.insert(
            key,
            LearnedMapping {
                device_id: result.device_id.clone(),
                original_method: result.method.clone(),
                learned_at_secs: now_secs,
                source_device: neighbor.device_id.clone(),
                source_port: Some(neighbor.interface.clone()),
                confidence: result.confidence,
            },
        );
    }

    /// Expire learned mappings older than TTL.
    /// Call at the start of each correlation cycle.
    pub fn expire_learned(&mut self, ttl: Duration, now_secs: i64) {
        let ttl_secs = ttl.as_secs() as i64;
        self.learned
            .retain(|_, v| (now_secs - v.learned_at_secs) < ttl_secs);
    }

    /// Invalidate learned mappings sourced from a port that has gone link-down.
    ///
    /// Prevents 24h hallucination when hardware is physically moved.
    /// Returns the number of mappings purged.
    pub fn invalidate_for_port(&mut self, device_id: &str, port_name: &str) -> usize {
        let before = self.learned.len();
        self.learned.retain(|_, v| {
            !(v.source_device == device_id
                && v.source_port.as_deref() == Some(port_name))
        });
        before - self.learned.len()
    }

    /// Dump learned mappings for the admin debug endpoint.
    pub fn audit_learned(&self, now_secs: i64) -> Vec<LearnedAuditEntry> {
        self.learned
            .iter()
            .map(|(key, v)| LearnedAuditEntry {
                key: key.clone(),
                device_id: v.device_id.clone(),
                original_method: format!("{:?}", v.original_method),
                learned_at_secs: v.learned_at_secs,
                source_device: v.source_device.clone(),
                source_port: v.source_port.clone(),
                confidence: v.confidence,
                age_secs: now_secs - v.learned_at_secs,
            })
            .collect()
    }

    /// Take ownership of learned mappings (for carrying forward to next cycle).
    pub fn take_learned(self) -> HashMap<String, LearnedMapping> {
        self.learned
    }

    // ── Private helpers ─────────────────────────────────────────

    /// Build a stable lookup key for a neighbor (identity preferred, then MAC).
    fn learned_key_for(&self, neighbor: &NeighborEntry) -> Option<String> {
        neighbor
            .identity
            .as_deref()
            .map(|id| format!("identity:{}", id.to_lowercase()))
            .or_else(|| {
                neighbor
                    .mac_address
                    .as_deref()
                    .map(|mac| format!("mac:{}", mac.to_uppercase()))
            })
    }

    /// Check if a key resolves via any authoritative (non-learned) map.
    fn resolves_via_registry(&self, key: &str) -> bool {
        if let Some(stripped) = key.strip_prefix("identity:") {
            return self.identity_exact.contains_key(stripped)
                || self.identity_normalized.contains_key(stripped)
                || self.routeros_identity.contains_key(stripped);
        }
        if let Some(stripped) = key.strip_prefix("mac:") {
            return self.mac_to_device.contains_key(stripped);
        }
        false
    }
}

// ── Utility ─────────────────────────────────────────────────────

/// Strip punctuation/whitespace and lowercase for fuzzy identity matching.
///
/// e.g. "MT-4011-R-Office" → "mt4011roffice" matches "MT4011ROffice".
pub fn normalize_identity(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '-' | '_' | '.' | ' '))
        .collect::<String>()
        .to_lowercase()
}
