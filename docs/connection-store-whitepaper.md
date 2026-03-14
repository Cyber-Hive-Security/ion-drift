# Connection Store — Technical Whitepaper

Ion Drift's persistent connection tracking engine, providing dual-ingestion flow
recording, GeoIP enrichment, anomaly flagging, and aggregate analytics over all
observed network traffic.

---

## 1. Overview

The **ConnectionStore** is a SQLite-backed subsystem that records every network
connection transiting the monitored Mikrotik RouterOS gateway. It fuses two
independent data sources — periodic conntrack polling and real-time syslog
events — into a single, deduplicated timeline of connection history. Each row is
enriched at insert time with GeoIP metadata (country, city, ASN, coordinates)
and classified as internal or external. Connections to operator-defined
"monitored regions" are automatically flagged for review.

The store exposes aggregate query methods consumed by the React frontend: a world
map (per-country and per-city), per-port Sankey diagrams, country drill-down
panels, paginated history tables, and weekly snapshots.

## 2. Data Ingestion

### 2a. RouterOS Conntrack Polling

A background task periodically calls the RouterOS REST API
(`/rest/ip/firewall/connection`) to retrieve the full connection table. Each
entry arrives as a `PollConnection` carrying a unique `conntrack_id`, protocol,
5-tuple, source MAC, TCP state, and byte counters (TX/RX).

`upsert_from_poll` looks up an existing open row by `conntrack_id`. If found, it
updates `last_seen`, byte counters, TCP state, and increments `poll_count`. If
not found, it inserts a new row with `data_source = 'poll'` and performs GeoIP
enrichment on the destination IP.

### 2b. Syslog UDP Listener

A tokio task (`spawn_syslog_listener`) binds a UDP socket and receives RouterOS
firewall log messages. Only packets from the configured router IP are accepted;
all others are silently dropped. Incoming lines are parsed by
`parse_routeros_syslog`, which expects the `ION` log-prefix:

```
<pri>MMM DD HH:MM:SS router firewall,info ION forward: in:IF out:IF, ...
    proto TCP (SYN), 1.2.3.4:80->5.6.7.8:443, len 60
```

The parser extracts protocol, source/destination IP:port (via the `->` arrow),
source MAC (`src-mac`), ingress interface (`in:`), and derives an action
(accept/drop/reject) from chain name or message content. Parsed events are
buffered into a batch (capacity 100) and flushed every 5 seconds or when full.

## 3. Connection Lifecycle

1. **First seen** — A new row is inserted with `closed = 0`, timestamped at
   current UTC. Poll entries carry `conntrack_id`; syslog entries do not.
2. **Active** — Subsequent polls update `last_seen`, byte counters, and
   `poll_count`. Syslog merges promote `data_source` from `'poll'` to `'both'`.
3. **Close (explicit)** — A syslog event with action `drop` or `reject` sets
   `closed = 1` and computes `duration_seconds`.
4. **Close (stale)** — `close_stale` compares active conntrack IDs against open
   rows. Any row whose `conntrack_id` is absent from the current poll set and
   whose `last_seen` exceeds the threshold is closed. Uses a temporary table of
   active IDs for efficient set-difference.
5. **Force-close** — During pruning, any open row with `last_seen` older than
   24 hours is force-closed.

## 4. GeoIP Enrichment

Destination IPs classified as external are enriched at insert time via the
`GeoCache`, a separate SQLite-backed lookup cache.

- **Primary source:** MaxMind GeoLite2 databases (Country + City + ASN),
  auto-downloaded on first run if API credentials are configured.
- **Fallback:** `ip-api.com` HTTP lookups for IPs not covered by MaxMind.
- **Caching:** Results are stored in `geo.db` to avoid repeated lookups.
  `lookup_cached` returns a hit from the cache without network I/O; only
  cache misses trigger a live lookup.
- **Fields stored per connection:** `geo_country_code`, `geo_country`,
  `geo_city`, `geo_asn`, `geo_org`, `geo_lat`, `geo_lon`.

## 5. Flow Classification

Each connection is classified along two axes at insert time:

- **Internal vs. external** — `geo::is_private()` tests the destination IP
  against RFC 1918 / RFC 6598 ranges. External connections receive GeoIP
  enrichment; internal ones are tagged with VLAN labels from the `VlanRegistry`.
- **Flagged regions** — The operator configures a list of monitored country
  codes (persisted in the switch store, overridable from the UI). If the
  destination's `geo_country_code` matches, the row is inserted with
  `flagged = 1`.

Port flows are further classified by `classified_port_summary` against computed
baselines: `Normal`, `NewPort`, `VolumeSpike`, `SourceAnomaly`, or
`Disappeared`.

## 6. History Storage

### Schema

A single table `connection_history` with columns grouped into:

| Group | Columns |
|-------|---------|
| Flow identity | `conntrack_id`, `protocol`, `src_ip`, `dst_ip`, `dst_port` |
| Context | `src_mac`, `src_vlan`, `src_hostname`, `dst_vlan`, `dst_hostname` |
| Lifecycle | `first_seen`, `last_seen`, `closed`, `last_state`, `duration_seconds` |
| Traffic | `bytes_tx`, `bytes_rx` |
| Observation | `data_source` (poll/syslog/both), `poll_count` |
| GeoIP | `dst_is_external`, `geo_country_code`, `geo_country`, `geo_city`, `geo_asn`, `geo_org`, `geo_lat`, `geo_lon` |
| Anomaly | `flagged`, `anomaly_id` |

### Indexes

- `idx_ch_conntrack` — partial index on `conntrack_id` where `closed = 0` (poll dedup)
- `idx_ch_flow` — partial index on flow tuple where `closed = 0` (syslog merge)
- `idx_ch_first_seen`, `idx_ch_last_seen` — time-range scans
- `idx_ch_geo` — country + time where external (world map)
- `idx_ch_src`, `idx_ch_src_mac_ts`, `idx_ch_dst_ip_ts` — device/Sankey queries
- `idx_ch_flagged` — partial index on flagged rows

### Retention

`prune(retention_days)` deletes closed rows older than the retention window
(default: 30 days) and force-closes any open row stale for more than 24 hours.

## 7. Analytics

### Per-Country Summary (`geo_summary`)

Aggregates external connections by `geo_country_code`: connection count, unique
sources/destinations, total bytes, top organizations, and flagged count.

### Per-City Summary (`city_summary`)

Groups by `geo_city` with a minimum connection threshold, returning coordinates
for map pin placement.

### Country Drill-Down (`country_summary`)

For a given country code, returns:
- **Top devices** — by `src_mac`, with hostname and byte totals
- **Top destinations** — by `dst_ip`, with organization name
- **Top ports** — by `dst_port` + protocol
- **Daily timeline** — `DATE(first_seen)` bucketed connection counts and bytes

### Per-Port Summary (`port_summary`)

Aggregated by `dst_port` + `protocol`, filterable by direction (outbound,
inbound, internal). Ephemeral ports (>= 49152) are excluded unless they exceed
1 GB total traffic.

### Classified Port Flows (`classified_port_summary`)

Compares current port activity against stored baselines
(`compute_port_flow_baselines`) to detect new ports, volume spikes, source
anomalies, and disappeared services. Links anomalies to specific devices via
the `anomaly_links` table.

### Paginated History (`query_history`)

Full-text filtered, paginated query with optional filters: `src_ip`, `dst_ip`,
`dst_port`, `protocol`, `country`, `closed`, `flagged`, `after`, `before`.

## 8. Syslog Parser

`parse_routeros_syslog` is a zero-allocation-friendly parser for RouterOS
firewall syslog lines:

1. Locate the `ION ` prefix (or fall back to `firewall` topic).
2. Extract the chain name (e.g., `forward`).
3. Identify protocol from `proto TCP` / `proto UDP` / `proto ICMP`.
4. Split the `SRC:PORT->DST:PORT` segment using the `->` arrow.
5. Extract `src-mac` and `in:` interface via substring search.
6. Derive action: `drop` if chain/message contains "drop", `reject` if
   "reject", otherwise `accept`.
7. Timestamp set to current UTC (RouterOS syslog timestamps lack precision).
8. Validate both IPs parse as `std::net::IpAddr` before returning.

Source IP validation in the listener ensures only the configured router can
inject events. Rejected packets are counted and logged (first 10 only).

## 9. Performance

- **WAL mode** — `PRAGMA journal_mode=WAL` with `synchronous=NORMAL` enables
  concurrent reads during writes without blocking the poll/syslog ingesters.
- **Conntrack dedup** — Partial index `idx_ch_conntrack` on open rows makes
  upsert lookups O(log n) over only active connections, not the full history.
- **Syslog batching** — Events are buffered (up to 100) and flushed in bulk
  every 5 seconds, amortizing lock acquisition and write overhead.
- **Temp table for stale detection** — `close_stale` loads active IDs into a
  temporary table for set-difference, avoiding O(n*m) scanning.
- **Ephemeral port filtering** — Port summaries exclude high-numbered ports
  with low traffic, keeping analytics queries fast and results meaningful.
- **Baseline significance filter** — `is_significant_port_flow` requires
  minimum thresholds (5 flows + 10 KB for non-well-known ports, 1 GB for
  ephemeral) to suppress internet scan noise from baselines.
