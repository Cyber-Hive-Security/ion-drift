# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.1] - 2026-03-17

### Added

- Lifetime Traffic column on Identities page showing all-time cumulative bytes per device
- Delta-based bandwidth tracking for accurate 1h/24h windowed traffic measurements
- MAC address enrichment on poll-sourced connections from router ARP/DHCP tables
- Bandwidth delta table with automatic 48-hour retention pruning
- Startup seeding of connection byte tracker to avoid inflation after restart
- System requirements section in README (pre-built image vs building from source)
- Building from source instructions (Rust, Node.js, cargo, npm)
- `docker-compose.build.yml` for source builds (separate from default pre-built image)

### Fixed

- Empty bandwidth columns on Identities page: ISO 8601 vs Unix timestamp comparison in SQL query
- 1h/24h traffic columns showed lifetime totals instead of windowed values (cumulative RouterOS counters were summed directly instead of computing deltas between polls)
- Behavior engine baselines trained on cumulative byte counts instead of deltas, producing absurd baselines (e.g. 326 TB/hr for a Plex server)
- Poll-sourced connections missing MAC addresses (RouterOS conntrack doesn't include MAC; now enriched from ARP/DHCP)
- Existing open connections now get MAC backfilled via COALESCE on update
- Investigate (Sankey) page showed no data when navigating from Identities — same root cause as missing MACs
- Default `docker-compose.yml` built from source instead of using pre-built image, causing OOM kills on low-spec VMs

### Changed

- "Reset Behavior Engine" button renamed to "Reset Baselines & Anomalies" with clearer description
- `docker-compose.yml` now pulls pre-built image from `ghcr.io/cyber-hive-security/ion-drift:latest`
- `docker-compose.example.yml` removed (replaced by `docker-compose.yml` + `docker-compose.build.yml`)
- Download/upload breakdown added to traffic column tooltips
- Connection poll loop uses HashSet for active ID tracking (O(1) vs O(n) lookups)

## [0.2.0] - 2026-03-16

### Added

- Per-manufacturer SNMP profile system for vendor-specific interface classification and naming
  - Netgear profile: filters port-channels, tunnels, and internal interfaces; uses short ifName values
  - Generic fallback profile preserves existing behavior for unknown vendors
- Per-port rate baselines using 168 hour-of-week buckets with exponential moving average (alpha=0.05)
- "vs Baseline" column in port traffic table showing current rate relative to learned baseline
- Per-client IPv4 bandwidth monitoring with RX/TX breakdown on Identities page
- Traffic (24h) column on Identities page
- Hardware limitations banner on switch detail page for devices with missing capabilities (e.g., CSS106 stats.b)
- SwOS board-specific PHY speed decoding (SwosSpeedClass: Gigabit vs MultiGig)
- port_index field threaded through storage, API, and frontend for reliable port grid positioning

### Fixed

- CRS326 byte counters: EthernetInterface serde fields renamed to match RouterOS API (rx-bytes/tx-bytes plural)
- CSS106 port grid: SwOS poller falls back to link.b when stats.b returns empty
- CSS106 speed: 1G ports no longer incorrectly shown as 100M (board-specific speed encoding)
- SNMP ifName walk flapping: partial failures now drop individual bad interfaces instead of corrupting the entire dataset
- SNMP port grid positioning: name parsing takes priority over portIndex (fixes 0-based vs 1-based mismatch)
- Utilization miscalculation from stale counter baselines after data purge
- port_index truncation: changed from u16 to u32 to handle SNMP ifIndex values above 65535
- Counter reset detection: log and skip ports with negative counter deltas instead of silent clamping
- Baseline EMA: fixed alpha=0.05 replaces cumulative average that froze over time
- Baseline hour-of-week uses UTC instead of local time (avoids DST bucket skipping)
- SQL parameterized queries for port name purge (replaces string interpolation)
- Baseline query errors now logged instead of silently returning empty results
- Removed dead props (macTable, onSelectPort) from PortTrafficTable component

### Security

- Replaced example coordinates in documentation and config files to prevent PII leak

## [0.1.0] - 2026-03-14

### Added

- RouterOS v7 REST API monitoring (system resources, interfaces, firewall rules, connections, DHCP, ARP)
- Multi-device management with support for RouterOS, SwOS, and SNMPv3 switches
- Connection tracking with persistent history and GeoIP enrichment (MaxMind)
- World map visualization with per-country connection summaries and city-level drill-down
- Behavioral anomaly detection with tiered severity (critical/warning/info) and deduplication
- Automated investigation engine with verdict classification (benign/routine/suspicious/threat)
- Anomaly suppression rules and bulk resolve/export workflows
- Network topology auto-discovery via LLDP/CDP neighbor data and MAC table correlation
- Topology inference engine with scored candidates, confidence tracking, and attachment state machine
- Interactive topology map with drag-to-position nodes and VLAN sector grouping
- Sankey flow visualization with four-level drill-down (network, VLAN, device, destination)
- Conversation detail view for per-device per-destination connection history
- Passive service discovery from connection tracking and firewall rules
- Port flow classification (normal/new_port/volume_spike/source_anomaly/disappeared)
- Firewall analytics with drop counters, country attribution, and per-interface breakdown
- Structured firewall log parsing with paired-message correlation
- VLAN traffic flow monitoring with per-VLAN activity rates and Sankey inter-VLAN flows
- VLAN configuration management (names, subnets, colors, sensitivity, media type)
- Local authentication with argon2id password hashing
- Generic OIDC support (Keycloak, Authentik, Authelia, or any OpenID Connect provider)
- Session management with listing and per-session revocation
- Encrypted secrets at rest using AES-256-GCM with key encryption key
- Ed25519 offline license key validation with evaluation/community/licensed/expired modes
- License expiry warnings and expired-state enforcement
- Setup wizard for first-run router provisioning (syslog, mangle, firewall rules)
- Device connection testing before saving credentials
- Alerting engine with configurable rules, severity/VLAN/disposition filters, and delivery channels
- Alert cooldowns, history tracking, and channel test endpoints
- Port MAC binding enforcement with violation detection and resolution
- Backbone link management for manual switch interconnect documentation
- Neighbor alias system for mapping or hiding LLDP/CDP neighbors in topology
- Network identity management with device type classification, disposition, and bulk actions
- DHCP pool utilization monitoring with ARP cross-reference
- Metrics history for CPU, memory, connections, drops, and per-VLAN traffic
- Log aggregate roll-ups and weekly snapshots for historical trending
- Syslog receiver for RouterOS remote logging
- GeoIP database update from settings UI
- Monitored regions configuration for geographic alerting
- TLS certificate status monitoring with auto-renewal support (CertWarden)
- Demo mode for sanitized screenshots (ION_DRIFT_MODE=demo)
- Dark-themed React frontend with Vite, TypeScript, TanStack Query, Tailwind CSS, and shadcn/ui
- CLI tool for direct RouterOS queries (system resources, interfaces, firewall, connections)
- Health check endpoint (no auth required)

### Security

- CSRF protection via Content-Type enforcement on mutating requests
- HMAC-SHA256 signed HttpOnly/Secure/SameSite=Lax session cookies
- Login rate limiting with automatic cleanup
- Security headers: X-Frame-Options DENY, X-Content-Type-Options nosniff, CSP, XSS protection
- CORS restricted to configured origin only
- Global auth guard middleware on all API routes (belt-and-suspenders with per-handler auth)
- Request body size limit (2 MiB)
- Router password stored as SecretString in memory
- SSRF bypass hardening on backend proxy requests
- PolyForm Shield 1.0.0 + CHS Use Agreement licensing
