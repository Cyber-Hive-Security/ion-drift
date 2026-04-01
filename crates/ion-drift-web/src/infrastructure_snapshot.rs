//! Resolved infrastructure snapshot — the platform's canonical view of network truth.
//!
//! Built atomically by the correlation engine after each cycle.
//! Consumed by: topology builder, and eventually Arc, alerting, export.
//!
//! **Governing principle:** Rendering the wrong answer cleanly is worse than
//! rendering uncertainty honestly.
//!
//! # Design invariants
//!
//! - This is a **platform contract**, not a topology convenience object.
//! - Every field must answer: "Is this part of resolved infrastructure truth?"
//!   If it is only convenient for one consumer, it does not belong here.
//! - Confidence values are **ordinal heuristics**, not calibrated probabilities.
//!   They support ranking and gating, not statistical inference.

use serde::{Deserialize, Serialize};

use ion_drift_storage::switch::NetworkIdentity;

// ── Constants ───────────────────────────────────────────────────

/// Maximum evidence entries per resolved node or edge.
/// Prevents memory growth from flapping LLDP neighbors or MAC spoofing.
/// FIFO: newest entries kept when cap is reached.
pub const MAX_EVIDENCE_ENTRIES: usize = 5;

// ── Snapshot ────────────────────────────────────────────────────

/// A complete, versioned snapshot of the resolved network infrastructure.
#[derive(Clone, Serialize, Deserialize)]
pub struct ResolvedInfrastructureSnapshot {
    /// Contract version. Increment when fields are added/removed/retyped.
    /// Consumers can use this for forward-compatible deserialization.
    pub schema_version: u16,

    /// Monotonically increasing generation counter.
    /// Topology only renders if generation > last rendered generation.
    pub generation: u64,

    /// When this snapshot was computed (Unix timestamp, seconds).
    pub computed_at: i64,

    /// The polling epoch that produced the source data.
    pub source_epoch: SourceEpoch,

    /// Whether this snapshot is complete, partial, or degraded.
    pub status: SnapshotStatus,

    /// Resolved infrastructure nodes (managed devices + inferred neighbors).
    pub infrastructure: Vec<ResolvedInfraNode>,

    /// Resolved trunk/backbone edges between infrastructure nodes.
    pub edges: Vec<ResolvedEdge>,

    /// WAN-facing neighbor count (for ISP placeholder rendering).
    pub wan_neighbor_count: u32,

    /// Network identities (endpoint devices) — produced by correlation.
    /// Included so topology has a single input, not two separate reads.
    pub identities: Vec<NetworkIdentity>,
}

/// Current schema version for `ResolvedInfrastructureSnapshot`.
pub const SNAPSHOT_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Serialize, Deserialize)]
pub struct SourceEpoch {
    /// Earliest poller data timestamp consumed in this snapshot (Unix secs).
    pub window_start: i64,
    /// Latest poller data timestamp consumed in this snapshot (Unix secs).
    pub window_end: i64,
    /// Correlation cycle number (monotonic, useful for debugging).
    pub cycle_number: u64,
}

/// Snapshot health status.
#[derive(Clone, Serialize, Deserialize)]
pub enum SnapshotStatus {
    /// All data sources contributed; resolution completed normally.
    Complete,
    /// Some data sources were unavailable or stale.
    Partial {
        degraded_sources: Vec<String>,
    },
    /// Snapshot failed validation. Do not render; fall back to last-known-good.
    Failed {
        reason: String,
    },
}

// ── Resolved infrastructure node ────────────────────────────────

/// A fully-resolved infrastructure device for platform consumption.
#[derive(Clone, Serialize, Deserialize)]
pub struct ResolvedInfraNode {
    /// Canonical device identifier (registered name or stable inferred ID).
    pub device_id: String,

    /// Human-readable label for display.
    pub label: String,

    /// How this node entered the snapshot.
    /// Answers: "Where did this node come from?"
    pub source: InfraNodeSource,

    /// Device classification (router, switch, access_point, etc.).
    pub device_type: Option<String>,

    /// MAC address (for cross-reference, dedup, evidence).
    pub mac: Option<String>,

    /// Best known IP address.
    pub ip: Option<String>,

    /// OUI manufacturer.
    pub manufacturer: Option<String>,

    /// VLAN membership with observability distinction.
    pub vlan_membership: Vec<VlanMembership>,

    /// Resolution confidence (0.0–1.0).
    /// Comparative heuristic, not a measured probability.
    pub confidence: f32,

    /// How this node's identity was resolved to a device_id.
    /// Answers: "How did we determine what this device is?"
    pub resolution_method: ResolutionMethod,

    /// Evidence chain that produced this node.
    /// Capped at [`MAX_EVIDENCE_ENTRIES`]. Newest kept, oldest dropped (FIFO).
    pub evidence: Vec<ResolutionEvidence>,

    /// Whether this node has conflicting or ambiguous resolution.
    pub conflict: Option<ConflictState>,

    /// First seen timestamp from underlying data (Unix secs).
    pub first_seen: Option<i64>,
    /// Last seen timestamp from underlying data (Unix secs).
    pub last_seen: Option<i64>,
}

/// How a node entered the snapshot.
///
/// Answers: "Where did this node come from?"
/// Does NOT answer how it was identified (see [`ResolutionMethod`])
/// or how authoritative the evidence is (see [`EvidenceAuthority`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InfraNodeSource {
    /// Registered in the device manager (managed device).
    Registered,
    /// Inferred from LLDP neighbor discovery.
    InferredLldp,
    /// Created from a backbone link definition.
    BackboneLink,
    /// Created from infrastructure identity (non-LLDP device like WAP).
    InfrastructureIdentity,
}

// ── Resolution method ───────────────────────────────────────────

/// How a node's identity was resolved to a device_id.
///
/// Answers: "What matching technique identified this device?"
/// Does NOT answer where the node came from (see [`InfraNodeSource`])
/// or how authoritative the evidence is (see [`EvidenceAuthority`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ResolutionMethod {
    /// Exact match on registered device name/id (lowercase).
    ExactIdentity,
    /// Fuzzy match via normalized identity (stripped non-alphanumeric).
    NormalizedIdentity,
    /// Matched via RouterOS health-check identity (MNDP broadcast string).
    RouterOsIdentity,
    /// Matched via IP address.
    IpAddress,
    /// Matched via MAC address fallback.
    MacFallback,
    /// Learned from a previous resolution cycle.
    Learned {
        original_method: Box<ResolutionMethod>,
    },
    /// Manual backbone definition (no dynamic resolution).
    ManualDefinition,
    /// No resolution needed — device is self-describing (registered + online).
    Authoritative,
}

// ── Evidence authority ──────────────────────────────────────────

/// Authority hierarchy for tie-breaking when sources disagree.
///
/// Answers: "How authoritative is this piece of evidence?"
/// Lower ordinal = higher authority. The `Ord` derive reflects this.
///
/// Does NOT answer what technique was used (see [`ResolutionMethod`])
/// or where the node came from (see [`InfraNodeSource`]).
///
/// # Tie-breaking rules
///
/// - Higher authority always wins the rendered result.
/// - LLDP vs Manual Backbone conflict → LLDP wins (packets > stale docs).
/// - Manual Backbone vs Inference conflict → Manual wins (intent > math).
/// - Confidence delta < 0.15 between winner/loser → flag as disputed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EvidenceAuthority {
    /// Human-confirmed identity or manually registered device.
    HumanConfirmed = 0,
    /// RouterOS primary device (REST API health check confirms identity).
    RouterPrimary = 1,
    /// Managed RouterOS switch (API-accessible, identity verified).
    RouterOsSwitch = 2,
    /// Managed switch via SNMP (identity from sysName/sysDescr).
    ManagedSwitchSnmp = 3,
    /// LLDP/MNDP neighbor observation (identity from remote system name).
    LldpObserved = 4,
    /// Admin-defined backbone link (explicit config when observation fails).
    ManualBackbone = 5,
    /// Topology inference engine (probabilistic MAC-table scoring).
    InferenceEngine = 6,
    /// Cached from prior resolution cycle.
    LearnedMapping = 7,
    /// Pre-SoA binding logic.
    LegacyFallback = 8,
}

// ── Evidence ────────────────────────────────────────────────────

/// A single piece of evidence supporting a resolution decision.
#[derive(Clone, Serialize, Deserialize)]
pub struct ResolutionEvidence {
    /// What kind of authority produced this evidence.
    pub authority: EvidenceAuthority,
    /// Where the evidence came from (e.g., "switch:css106", "neighbor:rb4011:ether5").
    pub source: String,
    /// What was observed (e.g., "LLDP identity 'MT-326-Office'").
    pub observation: String,
    /// When this evidence was observed (Unix timestamp, seconds).
    pub observed_at: i64,
}

/// Push evidence into a bounded vec, maintaining FIFO with [`MAX_EVIDENCE_ENTRIES`] cap.
pub fn push_evidence(evidence: &mut Vec<ResolutionEvidence>, entry: ResolutionEvidence) {
    if evidence.len() >= MAX_EVIDENCE_ENTRIES {
        evidence.remove(0);
    }
    evidence.push(entry);
}

// ── VLAN membership ─────────────────────────────────────────────

/// VLAN membership with source distinction.
#[derive(Clone, Serialize, Deserialize)]
pub struct VlanMembership {
    pub vlan_id: u32,
    /// How we know this device participates in this VLAN.
    pub source: VlanMembershipSource,
}

/// How VLAN membership was determined.
///
/// Answers: "How do we know this device is on this VLAN?"
/// These are NOT equivalent — do not flatten them visually.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VlanMembershipSource {
    /// VLAN is trunked on an observed port.
    ObservedTrunk,
    /// Active endpoint traffic seen on this VLAN.
    ObservedTraffic,
    /// Configured but no current traffic evidence.
    ConfiguredOnly,
    /// Inferred from access port membership.
    InferredAccess,
}

// ── Conflict state ──────────────────────────────────────────────

/// Conflict or ambiguity state for a node or edge.
#[derive(Clone, Serialize, Deserialize)]
pub struct ConflictState {
    /// What kind of conflict exists.
    pub kind: ConflictKind,
    /// Human-readable description.
    pub description: String,
    /// Alternative resolution(s) that were rejected. Max 3.
    /// Currently strings for pragmatism; may become structured in a future version.
    pub alternatives: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictKind {
    /// Two sources disagree on this node's identity.
    DisputedIdentity,
    /// Node resolved via low-authority method; may be wrong.
    LowConfidence,
    /// Manual backbone definition contradicts observed topology.
    BackboneContradiction,
    /// Multiple switches claim this MAC on different ports.
    DuplicateMac,
}

// ── Resolved edge ───────────────────────────────────────────────

/// A resolved trunk/backbone connection between two infrastructure devices.
#[derive(Clone, Serialize, Deserialize)]
pub struct ResolvedEdge {
    pub source_device: String,
    pub target_device: String,
    pub source_port: Option<String>,
    pub target_port: Option<String>,
    pub vlans: Vec<u32>,
    pub speed_mbps: Option<u32>,
    pub traffic_bps: Option<u64>,

    /// How this edge was discovered.
    /// Answers: "Why does this connection exist in the topology?"
    pub edge_source: EdgeSource,

    /// For backbone-defined edges: corroboration status.
    /// Re-evaluated every snapshot (microsecond check, no caching).
    pub corroboration: Option<EdgeCorroboration>,

    /// Confidence in this edge's existence (0.0–1.0).
    pub confidence: f32,

    /// Evidence chain. Capped at [`MAX_EVIDENCE_ENTRIES`].
    pub evidence: Vec<ResolutionEvidence>,
}

/// How an edge was discovered.
///
/// Answers: "Why does this connection exist?"
/// Does NOT imply confidence level (see `confidence` field).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeSource {
    /// Observed via LLDP neighbor discovery.
    LldpObserved,
    /// Defined via manual backbone link.
    BackboneDefined,
    /// Both: backbone definition confirmed by LLDP observation.
    BackboneCorroborated,
    /// Inferred from MAC table patterns (no direct LLDP or backbone).
    Inferred,
}

/// Corroboration status for backbone-defined edges.
///
/// Answers: "Does observed reality agree with this configured link?"
#[derive(Clone, Serialize, Deserialize)]
pub enum EdgeCorroboration {
    /// Backbone confirmed by LLDP or traffic observation.
    Corroborated { evidence: String },
    /// Backbone defined, no contradicting evidence, not observed.
    Unobserved,
    /// Backbone contradicts current LLDP/traffic evidence.
    Contradicted { evidence: String },
}

// ── Snapshot state management ───────────────────────────────────

/// Manages the active and last-known-good snapshots.
///
/// # Consumer contract (important for all consumers)
///
/// - `current` may be `Partial` — consumers should render what's available.
/// - `last_known_good` may be older than `current.source_epoch`.
/// - Do not assume freshness equality across snapshot fields.
/// - If `best_available()` returns `None`, no correlation cycle has completed yet.
pub struct InfrastructureSnapshotState {
    /// Current active snapshot (None before first correlation cycle completes).
    pub current: Option<ResolvedInfrastructureSnapshot>,
    /// Last snapshot that passed validation (for fallback).
    pub last_known_good: Option<ResolvedInfrastructureSnapshot>,
    /// Monotonically increasing generation counter.
    next_generation: u64,
}

impl InfrastructureSnapshotState {
    pub fn new() -> Self {
        Self {
            current: None,
            last_known_good: None,
            next_generation: 1,
        }
    }

    /// Next generation number for snapshot builders.
    pub fn next_generation(&self) -> u64 {
        self.next_generation
    }

    /// Atomically publish a new snapshot.
    /// Complete/Partial snapshots replace current; Failed snapshots are logged and discarded.
    pub fn publish(&mut self, snapshot: ResolvedInfrastructureSnapshot) {
        match snapshot.status {
            SnapshotStatus::Complete | SnapshotStatus::Partial { .. } => {
                self.last_known_good = self.current.take();
                self.current = Some(snapshot);
            }
            SnapshotStatus::Failed { ref reason } => {
                tracing::warn!(
                    generation = snapshot.generation,
                    reason = %reason,
                    "snapshot failed validation, retaining last-known-good"
                );
            }
        }
        self.next_generation += 1;
    }

    /// Best available snapshot for consumers.
    /// Returns current if available, otherwise last-known-good.
    pub fn best_available(&self) -> Option<&ResolvedInfrastructureSnapshot> {
        self.current.as_ref().or(self.last_known_good.as_ref())
    }
}

impl Default for InfrastructureSnapshotState {
    fn default() -> Self {
        Self::new()
    }
}
