# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
