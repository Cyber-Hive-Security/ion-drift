# ion-drift — Feature List

> **Last updated:** 2026-03-30

## Overview

ion-drift is a Rust-based network monitoring, security analytics, and device management platform for MikroTik RouterOS networks. It manages a primary router plus multiple managed switches with automatic device discovery, behavioral anomaly detection, and topology visualization. Dual interface: CLI tool + Axum web server serving a React frontend. Deployed as a Docker container behind a reverse proxy.

**Tech Stack:**
- Backend: Rust (Axum, Tokio, SQLite, `secrecy` for credential handling)
- Frontend: React 19 (Vite, TypeScript, TanStack Router + Query, Recharts, D3.js, Tailwind CSS 4)
- Router API: RouterOS v7 REST over HTTPS with custom CA support

---

## Monitoring

- Real-time system resource monitoring (CPU, memory, disk, uptime) via RouterOS REST API
- Multi-device management with CRUD operations, connection testing, and per-device polling intervals
- SNMP v3 polling for managed switches (port metrics, MAC tables, VLAN membership)
- Per-manufacturer SNMP profiles for vendor-specific interface classification (Netgear, HPE/Aruba, Cisco SMB, Generic)
- SwOS support for MikroTik budget switches with board-specific PHY speed decoding
- Hardware limitations banner for devices that don't expose full capabilities
- Live traffic rates per interface with historical time-series
- Per-VLAN traffic activity tracking and inter-VLAN flow analysis
- Firewall rule viewer (filter, NAT, mangle) with drop statistics and geo-enriched drop summaries
- Connection tracking with real-time summary and paginated detail view
- Structured log viewer with severity classification, analytics, and trend roll-ups
- Syslog receiver for real-time firewall event capture
- DHCP lease monitoring with ARP cross-reference and pool utilization metrics
- Historical metrics storage for CPU, memory, drops, connections, and VLAN traffic

## Network Discovery

- Passive service discovery from observed connection patterns (no active scanning required)
- Device fingerprinting via OUI manufacturer lookup and traffic pattern classification
- Automatic device type inference (camera, printer, server, phone, smart home, computer, media server) from behavioral heuristics
- Network identity correlation combining DHCP, ARP, switch MAC tables, LLDP/CDP neighbors, and nmap results
- Identity confidence scoring with human confirmation override
- Device disposition management (unknown, my_device, external, ignored, flagged)
- Port role detection (uplink, access, trunk) from MAC count and LLDP neighbor data
- Port MAC binding enforcement with violation detection and alerting

## Connection Tracking

- Real-time conntrack polling with protocol, state, and delta-based byte counter tracking
- MAC address enrichment on poll connections from router ARP/DHCP tables
- Syslog event capture for firewall drops with structured parsing
- Connection history with configurable retention and paginated queries
- GeoIP enrichment for external connections (country, city, ASN, organization)
- Per-country drill-down with top devices, destinations, ports, and timeline
- Per-port traffic summary with flow counts and unique source/destination counts
- Weekly connection snapshots for historical trend analysis
- Flagged connection tracking for monitored regions

## Security Analytics

- Behavioral anomaly detection with per-device learned baselines (delta-based byte tracking)
- Five anomaly types: new destination, new port, new protocol, volume spike, blocked attempt
- Three-stage volume spike validation (absolute floor, baseline comparison, multi-window persistence)
- Tiered anomaly architecture: Tier 1 (alerts), Tier 2 (digests), Tier 3 (telemetry)
- Automated investigation engine producing verdicts (benign, routine, suspicious, threat, inconclusive) with evidence chains
- Policy-aware detection: infrastructure policy sync from router DHCP/DNS/firewall config
- Shadow service detection for unauthorized protocol servers (DNS, NTP, DHCP, LDAP, SMB, SNMP, syslog, SMTP)
- Firewall comment tags for operator control: `[ION-CRITICAL]` and `[ION-IGNORE]`
- Firewall rule correlation on every anomaly (expected allow, expected deny, policy unknown)
- VLAN-aware severity scaling with five sensitivity levels (strictest through monitor)
- CDN/cloud provider detection via ASN whitelist (60+ major providers)
- Monitored region/country flagging with configurable watchlist
- WAN scan pressure aggregation with time-series dashboard
- Port flow baselines with network-wide anomaly classification (new port, volume spike, source anomaly, disappeared)
- Two-layer correlation: device-level anomalies cross-linked with network-level port anomalies
- **DNS policy deviation detection** with MITRE ATT&CK context — detects devices using unauthorized DNS servers, enriches with ATT&CK technique mappings (T1071.004, T1568, T1048.003, T1583.001), resolve actions create policies organically
- **NTP policy deviation detection** with MITRE ATT&CK context — detects devices using unauthorized NTP servers (T1124), policies auto-synced from DHCP option 42
- **Policy editor** — create, edit, and delete custom network policies via the UI. Admin policies protected from router sync overwrite. Router-synced policies locked (read-only)
- **Deviation enrichment** — device hostnames, GeoIP org names for external IPs, per-VLAN severity, CSV export with formula injection defense
- **Blocked connection filtering** — firewall-blocked connections (zero reply bytes) excluded from deviation detection. Router WAN IP excluded from detection via `ip/dhcp-client`
- Pattern suppression rules with auto-creation on operator dismiss
- Priority boosting on operator flag (persistent severity escalation)
- Deduplication with occurrence counting and last-occurrence tracking
- Confidence scoring based on baseline maturity, observation depth, firewall correlation, and VLAN sensitivity
- Anomaly CSV export with full context (severity, flow, VLAN, policy, traffic class, zones)
- Full behavior engine reset with suppression rule preservation

## Visualization

- Interactive network topology map with automatic layout and manual position persistence
- VLAN sector grouping with color-coded subnets and drag-to-reposition
- Backbone link management for manual switch interconnects
- Neighbor alias management (alias LLDP/CDP neighbors to known devices or hide them)
- Topology inference engine with scored candidate evaluation, confidence tracking, and divergence detection
- Sankey flow diagrams: network overview, per-VLAN device flows, per-device protocol/destination breakdown, conversation drill-down
- World map with GeoIP-enriched connection visualization (country and city summaries)
- Per-country detail view with top devices, destinations, ports, and timeline
- VLAN flow diagrams showing inter-VLAN traffic volumes
- Real-time interface traffic charts
- Historical time-series charts for CPU, memory, firewall drops, connections, and VLAN traffic
- Port utilization display with speed detection and rate calculation
- Per-port rate baselines with hour-of-week EMA and "vs Baseline" column
- Per-client IPv4 bandwidth monitoring with RX/TX breakdown on Identities page
- Lifetime traffic column showing all-time cumulative bytes per device
- Delta-based bandwidth tracking for accurate 1h/24h windowed traffic

## Authentication

- Local authentication with username/password
- Generic OIDC support (Keycloak, Authentik, Authelia, or any OIDC-compliant provider) with PKCE flow
- HMAC-signed session cookies with configurable expiry
- Session management UI with active session listing and individual revocation
- Global auth middleware on all API routes (defense-in-depth alongside per-handler extractors)
- CSRF protection via Content-Type enforcement on mutating requests
- Login rate limiting with IP validation (rightmost XFF, verified as IpAddr)
- Setup wizard bootstrap token (one-time token logged to stdout, prevents unauthorized setup claims)

## Encryption

- AES-256-GCM encryption for all secrets at rest (router credentials, OIDC secrets, API keys)
- Argon2id password hashing for local accounts
- Key encryption key (KEK) via local argon2id derivation (default), OIDC client secret derivation (OIDC without mTLS), or mTLS Keycloak bootstrap (opt-in)
- Random persistent salt for KEK derivation (unique per installation)
- Key fingerprint tracking with per-secret currency status
- Session secret regeneration on demand

## Licensing

- PolyForm Shield License 1.0.0 + CHS Use Agreement
- Ed25519 offline license key verification (no phone-home)
- License tiers: evaluation (30-day), community, business, education, nonprofit, government
- Device count limits per license tier
- Graceful degradation on expiry with acknowledgment flow

## Alerting

- Configurable alert rules with event type, severity, VLAN, disposition, and verdict filters
- Multi-channel delivery (extensible channel architecture)
- Per-rule cooldown periods to prevent alert storms
- Alert history with channel success/failure tracking
- Channel configuration and test endpoints

## Administration

- **Router request queue** — serializes all background API requests through a priority-scheduled queue with adaptive gap control, circuit breaker, deduplication, and starvation detection. Prevents concurrent TLS sessions from overwhelming low-end routers.
- Configurable poll intervals via `[polling]` config section (traffic, metrics, connections, behavior, correlation, topology, policy sync)
- In-app restart from Settings → Devices with "Restart Now" / "I'll do it later" prompt
- Auto-detect CA cert at `/app/certs/root_ca.crt` without config (convention over configuration)
- Env var credential migration to encrypted secrets DB on first run
- Statistics page with page view tracking, diagnostic report generation, and engine health overview
- Graceful startup when router is unreachable — web UI starts so credentials can be fixed via Settings
- HTTP compression (gzip + Brotli) and immutable cache headers for hashed static assets
- Settings management for map configuration, monitored regions, and GeoIP database updates
- Secrets management UI showing encryption status, key currency, and per-secret metadata
- TLS certificate status monitoring with auto-renewal support
- Device CRUD with connection testing and provisioning wizard
- VLAN configuration (name, subnet, color, media type, sensitivity level) stored in database
- Router provisioning planner: generates and applies mangle rules, syslog config, and firewall rules
- Demo mode with automatic PII sanitization on all API responses
- About section in Settings → System showing version, license, and publisher
- Health check endpoint for container orchestration
- Security headers (X-Frame-Options, CSP, X-Content-Type-Options, X-XSS-Protection)
- CORS configuration derived from OIDC redirect URI
