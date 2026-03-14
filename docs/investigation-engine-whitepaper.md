# Ion Drift Investigation Engine

## Overview

The investigation engine is an automated anomaly enrichment and verdict system
built into ion-drift. When the behavior engine detects an anomaly (new
destination, new port, volume spike, or blocked attempt), the investigation
engine gathers contextual data from local stores, applies a deterministic
rule chain, and produces an actionable verdict. All queries hit local SQLite
and in-memory caches -- no external API calls are made in the hot path. The
design target is under 500 ms per investigation.

## Trigger

An investigation is triggered whenever the behavior engine records a new
anomaly. The entry point is `InvestigationEngine::investigate(anomaly_id)`,
which accepts the database ID of the anomaly and runs the full pipeline
synchronously (async Rust, but single-pass -- no retries or queues).

Anomaly types that trigger investigations:

- `new_destination` -- device contacted an IP it has never talked to before
- `new_port` -- device used a destination port outside its baseline
- `volume_spike` -- traffic volume exceeded the device's learned baseline
- `blocked_attempt` -- firewall denied traffic involving this device

## Context Gathering

The engine collects six categories of context before rendering a verdict.

### 1. Device Profile

Source: `BehaviorStore::get_profile(mac)` and anomaly metadata.

| Field | Description |
|-------|-------------|
| MAC address | Layer-2 identifier from the anomaly |
| Hostname | Resolved hostname from the device profile |
| Manufacturer | OUI-derived vendor name |
| Disposition | `"flagged"` if operator previously flagged any anomaly for this device, else null |
| Baseline status | `learning`, `sparse`, or `baselined` -- how mature the device's behavioral model is |
| First seen | Unix timestamp of when the device first appeared on the network |
| VLAN sensitivity | Per-VLAN sensitivity tier from the VLAN registry: `strictest`, `strict`, `moderate`, `loose`, or `monitor` |

### 2. Destination Analysis

Sources: anomaly details JSON, `GeoCache` (MaxMind), `ConnectionStore`.

| Field | Description |
|-------|-------------|
| IP | Destination IP extracted from anomaly details (CIDR suffix stripped) |
| Country / City | GeoIP lookup via the in-memory geo cache |
| ASN / Org | Autonomous system number and organization name |
| CDN flag | True if the ASN matches a known CDN/cloud provider (Cloudflare, Akamai, AWS, Google, Microsoft, etc. -- 30+ ASNs tracked) |
| Flagged country | True if the destination country appears in the operator-configured monitored-regions list |
| Reverse DNS | Reserved field for future rDNS lookups |
| Seen-by count | Number of distinct devices on the network that have communicated with the same destination IP in the past 7 days |

### 3. Behavioral History

Source: `BehaviorStore` aggregate queries.

| Field | Description |
|-------|-------------|
| Prior anomalies (24h) | Total anomaly count for this MAC in the last 24 hours |
| Prior anomalies (7d) | Total anomaly count for this MAC in the last 7 days |
| Same-pattern count (24h) | How many anomalies of the exact same type occurred for this MAC in 24 hours |
| Baseline coverage % | Ratio of baselined flows to total observed flows (0-100%) |

### 4. Traffic Volume

Source: anomaly details JSON fields `projected_hourly` and `baseline_max`.

| Field | Description |
|-------|-------------|
| Current volume | Projected hourly byte count at the time of the anomaly |
| Baseline volume | Maximum hourly byte count from the learned baseline |
| Volume ratio | `current / baseline` -- how many multiples above normal |

### 5. Network Context

Source: `BehaviorStore` windowed queries (1-hour window).

| Field | Description |
|-------|-------------|
| Unique destinations (1h) | Distinct destination IPs this device contacted in the last hour |
| Unique ports (1h) | Distinct destination ports this device used in the last hour |

### 6. Firewall Correlation

Source: anomaly record fields populated by the behavior engine's firewall matcher.

| Field | Description |
|-------|-------------|
| Rule ID | Mikrotik firewall rule `.id` that matched |
| Action | Policy outcome (`expected_allow`, `expected_deny`, etc.) |
| Rule comment | Human-readable comment on the matched firewall rule |
| Correlation | Firewall correlation tag (e.g., `expected_deny`, `expected_allow`) |

## Verdict Algorithm

The engine evaluates a fixed rule chain. The first matching rule wins.

### Policy Rules (P1-P5)

These fire when the anomaly involves a recognized service protocol (DNS, NTP,
DHCP, LDAP, SMB, SNMP, syslog, SMTP) and a policy entry exists.

| Rule | Condition | Verdict | Action |
|------|-----------|---------|--------|
| **P4** | Firewall rule comment contains `[ION-CRITICAL]` | `threat` | `escalate` |
| **P5** | Firewall rule comment contains `[ION-IGNORE]` | `benign` | `no_action` |
| **P1** | Destination is authorized for the service in the policy table | `benign` | `no_action` |
| **P2** | Destination is NOT authorized but firewall allows it (shadow service). Escalated to `threat` if 2+ corroborating signals present (flagged device, 3+ repeats, strict VLAN, flagged country, zero other devices seen). | `suspicious` or `threat` | `investigate` or `escalate` |
| **P3** | Destination is NOT authorized and firewall blocked it (`expected_deny`) | `routine` | `no_action` |

### Behavioral Rules (evaluated if no policy rule matched)

| Rule | Condition | Verdict | Action |
|------|-----------|---------|--------|
| **1** | Device disposition is `flagged` | `suspicious` | `escalate` |
| **2** | Blocked attempt from WAN source zone | `routine` | `no_action` |
| **3** | Blocked attempt with `expected_deny` correlation | `benign` | `no_action` |
| **4** | New destination to a CDN provider (ASN match) | `benign` | `no_action` |
| **5** | New destination seen by 3+ other devices in 7 days | `benign` | `no_action` |
| **6** | New port is a roaming protocol (DNS, DHCP, NTP, mDNS, SSDP, STUN, NetBIOS) | `benign` | `no_action` |
| **7a** | Volume spike < 5x on a device with sparse baseline | `routine` | `monitor` |
| **7b** | Volume spike > 20x baseline | `suspicious` | `investigate` |
| **8** | New destination to a flagged/monitored country | `suspicious` | `investigate` |
| **9** | Device is still in the learning period | `routine` | `no_action` |
| **10** | Same anomaly pattern occurred 3+ times in 24h | `suspicious` | `investigate` |
| **default** | No rule matched | `inconclusive` | `monitor` |

### Evidence Chain

Every rule evaluation appends an `EvidenceStep` to a vector:

```json
{ "check": "CDN detection", "result": "Destination is CDN: Cloudflare", "passed": true }
```

The full evidence chain is serialized to JSON and stored with the investigation
record, providing a transparent audit trail of why a verdict was reached.

## Output

Each investigation produces a `NewInvestigation` record containing:

- **Anomaly link**: `anomaly_id` tying back to the source anomaly
- **Device context**: MAC, hostname, manufacturer, disposition, first-seen, baseline status
- **VLAN context**: VLAN ID and sensitivity tier
- **Destination context**: IP, country, city, ASN, org, CDN flag, reverse DNS, seen-by count
- **Behavioral context**: prior anomaly counts (24h/7d), same-pattern count, baseline coverage %
- **Traffic context**: current volume, baseline volume, volume ratio, unique destinations/ports (1h)
- **Firewall context**: rule ID, action, comment, correlation
- **Verdict**: one of `benign`, `routine`, `suspicious`, `threat`, `inconclusive`
- **Recommended action**: `no_action`, `monitor`, `investigate`, or `escalate`
- **Reason**: one-line explanation of why the verdict was chosen
- **Summary**: human-readable narrative (e.g., "printer-office (online for 12 days, fully baselined) -- new destination to 1.2.3.4, US, Cloudflare, CDN. New destination is CDN provider (Cloudflare)")
- **Evidence chain**: JSON array of every check performed
- **Timestamps**: `investigated_at` (epoch seconds), `duration_ms`

The verdict also updates the anomaly's tier in the database: `threat`/`suspicious` set tier 1,
`inconclusive` sets tier 2, and `benign`/`routine` set tier 3.

## Performance

- **Target latency**: < 500 ms per anomaly (stated design goal).
- **Data sources**: all local -- SQLite queries via `BehaviorStore`, in-memory `GeoCache`, in-memory `ConnectionStore`. No network round-trips.
- **Execution model**: single async function per anomaly. Investigations run inline when triggered by the behavior engine. Each investigation is timed via `std::time::Instant` and the elapsed milliseconds are stored in `duration_ms`.
- **No batching**: each anomaly is investigated individually as it is detected. The engine is stateless between investigations -- no cross-anomaly deduplication or grouping occurs at the investigation layer.
