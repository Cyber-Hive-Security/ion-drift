# Ion-Drift Behavior Engine

## Overview

The behavior engine continuously monitors network devices, learns their traffic patterns, detects anomalies, and automatically investigates findings. It operates as a multi-stage pipeline: observe, profile, baseline, detect, correlate, investigate, and present.

## Device Profiling

Every device on the network is tracked by MAC address. Each device profile records:

- **Hostname** (from DHCP leases) and **manufacturer** (from OUI database)
- **Current IP and VLAN**
- **First seen / last seen** timestamps
- **Baseline status**: one of `learning`, `sparse`, or `baselined`

### Lifecycle

Devices begin in a **7-day learning period**. During learning, the engine collects observations but does not generate behavioral anomalies (blocked connection attempts are still flagged immediately). After the learning period, the device is promoted:

- **Baselined** — at least 3 distinct flow tuples and 50 total observations. Full anomaly detection at highest confidence.
- **Sparse** — insufficient observations for full profiling. Anomaly detection runs with reduced confidence scores.

Promotions are checked every 10 minutes and during nightly maintenance at 3 AM.

## Observation Collection

Every 60 seconds (after a 3-minute startup delay), the collector fetches the router's ARP table, DHCP leases, and firewall connection tracking. Connections are aggregated by `(MAC, protocol, dst_port, dst_subnet, direction)` and stored as observations with bytes sent/received and connection count.

Destinations are classified by the VLAN registry: known VLAN subnets use their CIDR, other private IPs are grouped as /24, and public IPs as /16. Direction is classified as outbound, inbound, lateral (cross-VLAN), or internal (same VLAN).

## Baseline Computation

Baselines are recomputed nightly at 3 AM over a 7-day window. For each unique flow tuple per device, the engine calculates average bytes per hour, maximum bytes per hour, and total observation count. Observations older than 30 days are pruned.

A device's baseline is its behavioral fingerprint — the full set of protocol/port/destination/direction tuples it normally uses, along with traffic volume profiles for each.

## Anomaly Detection

Detection runs every 60 seconds on baselined and sparse devices.

### Anomaly Types

- **new_destination** — device contacts a subnet not in its baseline
- **new_port** — device uses a port not in its baseline for a known destination
- **new_protocol** — device uses a protocol not in its baseline
- **volume_spike** — traffic volume exceeds baseline thresholds (requires 3-stage validation: absolute floor of 5 MB/hr, 3x max and 5x avg baseline, and persistence across 2 of the last 5 polls)
- **blocked_attempt** — firewall dropped an inbound connection attempt

### Deduplication

Each anomaly has a `dedup_key` (e.g., `dst_subnet|protocol|dst_port`). If a pending anomaly with the same device, type, and dedup key already exists, the engine increments `occurrence_count` and updates `last_occurrence` instead of creating a duplicate.

### Enrichment

Every anomaly is enriched with:

- **Traffic class**: dhcp_activity, management_protocol, internet_scan, lateral_movement, internal_service_access, external_service_access, etc.
- **Source/destination zones**: Guest, IoT, Services, Management, WAN, etc.
- **Firewall correlation**: matched against the cached firewall ruleset to determine if traffic is expected_allow, expected_deny, or policy_unknown
- **GeoIP**: country, city, ASN, organization for external destinations

## Tiered Anomaly Architecture

Anomalies are classified into three tiers that control visibility and urgency:

| Tier | Name | Purpose |
|------|------|---------|
| **1** | Alert | Policy violations, threats, operator-escalated items. Always visible with badge count. |
| **2** | Digest | Behavioral shifts that are policy-compliant. Grouped by device + type in the UI. |
| **3** | Telemetry | Benign/routine detections for forensic lookback. Hidden by default. |

Tier assignment is driven by the auto-investigation verdict: threat/suspicious maps to Tier 1, inconclusive to Tier 2, and benign/routine to Tier 3. Firewall comment tags `[ION-CRITICAL]` and `[ION-IGNORE]` can override tiers directly.

## Auto-Investigation Engine

Every new anomaly is automatically investigated within seconds. The engine gathers five layers of context and applies a prioritized rule chain to produce a verdict. All queries run against local SQLite and in-memory caches — no external API calls. Target latency: under 500ms per anomaly.

### Context Layers

1. **Device** — hostname, manufacturer, disposition, baseline status, VLAN sensitivity, learning status
2. **Destination** — GeoIP (country, city, ASN, org), CDN detection (60+ major provider ASNs), commonality (how many other devices contact this IP)
3. **Behavioral** — anomaly counts (24h, 7d), same-pattern recurrence, baseline coverage percentage
4. **Traffic** — current vs. baseline volume, volume ratio, unique destinations and ports in the last hour
5. **Firewall** — matched rule ID, action, comment, correlation type

### Verdict Rules (applied in order, first match wins)

**Policy rules (highest priority):**

- **P4: ION-CRITICAL** — traffic matched a firewall rule tagged `[ION-CRITICAL]` → threat, escalate
- **P5: ION-IGNORE** — traffic matched a firewall rule tagged `[ION-IGNORE]` → benign, no action
- **P1: Authoritative Service** — destination is in the infrastructure policy map for this protocol (DNS, NTP, DHCP, LDAP, SMB, SNMP, syslog, SMTP) → benign, no action
- **P2: Shadow Service** — destination is NOT in the policy map but firewall allows it → suspicious (escalates to threat with corroborating evidence: flagged device, recurring pattern, strict VLAN, flagged country, zero peer commonality)
- **P3: Blocked Non-Authoritative** — non-policy destination blocked by firewall → routine, no action

**Behavioral rules:**

1. Flagged device → suspicious, escalate
2. Blocked inbound from WAN → routine (internet noise)
3. Expected firewall deny → benign
4. CDN destination → benign
5. Common destination (seen by 3+ devices) → benign
6. Roaming protocol port (DNS, DHCP, NTP, mDNS, SSDP, STUN) → benign
7. Volume spike assessment (sparse baseline + moderate ratio → routine; extreme ratio > 20x → suspicious)
8. Flagged country → suspicious
9. Learning device → routine
10. Recurring pattern (3+ same-type anomalies in 24h) → suspicious

Default: inconclusive, monitor.

### Verdicts

| Verdict | Meaning |
|---------|---------|
| benign | Expected behavior, no risk |
| routine | Normal operational noise |
| suspicious | Warrants operator attention |
| threat | Active threat indicator |
| inconclusive | Insufficient evidence |

Each investigation produces a human-readable summary and an evidence chain documenting which checks passed or failed.

## Policy Sync

The engine syncs infrastructure policies from the router's DHCP options, DNS configuration, IP routes, and firewall rules. This creates a policy map of authoritative servers for critical protocols (DNS, NTP, DHCP, LDAP, SMB, SNMP, syslog, SMTP). Traffic to policy-authorized destinations is automatically classified as benign; traffic to non-authorized destinations on policy-tracked protocols triggers shadow service detection.

## VLAN-Aware Detection

All anomalies are tagged with the source device's VLAN. The behavior overview provides per-VLAN summaries showing device counts, baseline status distribution, and pending anomaly counts.

Each VLAN has a configurable sensitivity level that controls anomaly severity and auto-resolution:

| Sensitivity | Severity Floor | Auto-Resolve |
|-------------|---------------|--------------|
| Strictest | critical | Never |
| Strict | alert/warning | Never |
| Moderate | warning/info | 48 hours |
| Loose | warning/info | 24 hours |
| Monitor | info | 72 hours |

Stale anomalies on less-sensitive VLANs are automatically resolved hourly.

## Port Flow Baselines

Independent of per-device baselines, the engine maintains network-wide port flow baselines computed from 7 days of connection history. These track per-port aggregate bytes, connection counts, and typical source/destination IPs. Port flows are classified as normal, new_port, volume_spike, source_anomaly, or disappeared. A scan noise filter prevents internet probes from polluting baselines.

The anomaly correlator cross-links device-level anomalies with port-level anomalies, producing compound findings (e.g., "Device X is responsible for the anomalous traffic on port Y"). Correlated anomalies receive elevated severity.

## WAN Scan Pressure

Inbound WAN scan attempts are aggregated into 5-minute buckets rather than generating individual anomalies. The dashboard shows probe rates, top targeted ports, and top source countries over time.

## Traffic Pattern Classification

During nightly maintenance, the engine classifies devices by their traffic patterns using heuristic rules on dominant ports, bandwidth ratios, and connection diversity. Classifications include camera, printer, media_server, smart_home, phone, computer, and server. Classifications update the device's network identity only when the new confidence exceeds the existing value and no human confirmation exists.

## Operator Workflow

- **Accept** — incorporates the behavior into the device's baseline on next recomputation
- **Dismiss** — auto-creates a suppression rule to prevent future duplicates of the same pattern
- **Flag** — increments a priority boost that escalates future severity for this pattern

Suppression rules filter by device, VLAN, protocol, port, and traffic class (all optional — NULL acts as wildcard). Priority boosts persist indefinitely, escalating severity one step per boost level (info → warning → alert → critical).

## Confidence Scoring

Each anomaly receives a confidence score (0.0-1.0) based on: baseline status (+0.15 baselined, -0.10 sparse), observation count, baseline age, firewall correlation (+0.15), VLAN sensitivity, anomaly type, and priority boosts (+0.05 per level).

## API

The behavior engine exposes endpoints for:

- Overview stats and per-VLAN summaries
- Device detail with profile, baselines, anomalies, and port flow contexts
- Anomaly listing with filters (status, severity, VLAN, tier), resolution, bulk actions, CSV export, and full deletion/reset
- Suppression rule management
- Investigation listing, per-anomaly and per-device queries, and verdict statistics
- Anomaly link correlation (port-level and device-level)
- WAN scan pressure time series
- Alert counts (pending, critical, warning, Tier 1)
