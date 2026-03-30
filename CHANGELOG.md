# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.8]

### Added

- **Bundled DB-IP Lite GeoIP databases** — Docker image now includes DB-IP Lite City and ASN databases for out-of-box GeoIP support. World map, country summaries, and deviation enrichment (org names) work immediately without a MaxMind account. MaxMind GeoLite2 takes priority if the user provides their own files.
- **GeoIP source indicator** — Settings → System → GeoIP section now shows which database source is active ("MaxMind GeoLite2" or "DB-IP Lite") with appropriate attribution text.
- **DB-IP attribution** — CC BY 4.0 license attribution displayed in the GeoIP settings section when DB-IP Lite is the active source.

### Changed

- **GeoIP provider fallback chain** — `MaxMind GeoLite2 → DB-IP Lite → none`. The provider loads the first available database set from the geoip directory, preferring MaxMind if both exist.

## [0.3.7] - 2026-03-30

### Security

- **Setup wizard bootstrap token** — both OIDC and local setup modes now generate a one-time random token logged to stdout. The setup form requires this token, preventing unauthorized setup claims on shared networks.
- **X-Forwarded-For hardening** — login rate limiter now uses the rightmost XFF entry (set by nearest proxy, harder to spoof) and validates values as IP addresses.
- **KEK file permissions** — `machine.key` and `kek.local` are now chmod 0600 on Unix after creation, preventing other users from reading key material.
- **WAN IP parameterized query** — replaced string interpolation with bound SQL parameter for router WAN IP exclusion in the deviation detector.
- **CSV formula injection defense** — CSV export sanitizes cells starting with `=`, `+`, `-`, `@` by prefixing with single quote to neutralize spreadsheet formula execution.

### Added

- **NTP deviation detection** — detects devices using unauthorized NTP servers (port 123/UDP). Same architecture as DNS detection with `ServiceType` enum. ATT&CK technique T1124 (System Time Discovery). NTP policies auto-synced from DHCP option 42.
- **Policy editor** — create, edit, and delete admin policies via the UI. Modal form with service, protocol, port, authorized targets, VLAN scope, and priority. Router-synced policies show a lock icon (not editable). Admin policies show edit/delete icons.
- **Policy CRUD API** — `POST /api/policy`, `PUT /api/policy/{id}`, `DELETE /api/policy/{id}` with input validation, hard conflict detection (409 on duplicate tuple), and soft conflict detection (overlapping CIDRs require `force=true`).
- **Admin policy protection** — `user_created` boolean column on infrastructure_policy table. Stale reaper skips admin policies. Sync cycle preserves admin-modified targets, source, and priority.
- **Deviation enrichment** — Device column shows hostname from behavior profiles. Expected and Actual columns show internal hostnames or GeoIP org names for external IPs (e.g., "Google LLC" for 8.8.8.8).
- **Delete All deviations button** — admin action on the policy page with confirmation dialog.
- **CSV export** — "Export CSV" button on policy deviations section. Includes device hostname, VLAN name, severity, ATT&CK IDs, and timestamps.
- **Deviation total count** — API returns `total_count` and `truncated` flag. Frontend shows warning when results exceed the limit.
- **Per-VLAN severity** — deviation severity computed from VLAN sensitivity (floor) and policy priority (escalation). Critical VLAN = critical deviation regardless of policy priority.
- **About section** — Settings → System now shows version, license (PolyForm Shield 1.0.0), and publisher (Cyber Hive Security LLC) with links.

### Fixed

- **Resolve actions generalized** — authorize/deny_all (now "Flag All") work for both DNS and NTP deviations via service-type prefix mapping.
- **VLAN-less resolve no-op** — authorize/Flag All now return 400 error if the deviation has no VLAN scope, instead of silently succeeding without creating a policy.
- **Blocked connections filtered** — detector only flags connections with `bytes_rx > 0` (bidirectional traffic). Firewall-blocked attempts are not deviations.
- **Router WAN IP excluded** — detector fetches WAN IP from `ip/dhcp-client` at startup and excludes router-originated traffic from deviation detection.
- **Admin policy sync protection** — upsert now uses CASE logic to skip overwriting targets/source/priority when the existing row is admin-protected and the incoming upsert is not from an admin action.
- **Resolved deviations hidden** — default deviation view excludes both `resolved` and `dismissed` status.
- **CSS106 limitation banner** — hardware limitation banner now shows when `stats.b` returns a parse error (Err path), not just empty Ok.
- **"Deny All" renamed to "Flag All"** — clarifies this is an observation policy, not router enforcement.
- **Authorize target cap** — merged target list capped at 1000 entries to prevent unbounded memory growth.

### Changed

- **Detector refactored** — DNS-specific detection logic extracted into generic `detect_port_service()` with `ServiceType` enum carrying protocol, port, skip_server_ips flag, and ATT&CK technique list.

## [0.3.6] - 2026-03-27

### Security

- **OsRng for all cryptographic random generation** — replaced `rand::random()` (ThreadRng) with `OsRng.try_fill_bytes()` for AES-256-GCM nonces, KEK generation, machine keys, argon2 salts, session tokens, and session secrets (13 call sites across 6 files). Non-crypto uses (backoff jitter, SwOS digest cnonce) left as `rand::random()`.
- **OsRng failures propagate gracefully** — RNG errors return 500/startup errors instead of panicking the process. Preserves existing error-handling contracts (`cache_kek` best-effort, `encrypt_value` returns Result, etc.).

### Fixed

- **DNS deviation false positives** — DNS servers were incorrectly flagged for performing recursive resolution. Exclusion now identifies DNS servers both from policy `authorized_targets` (DHCP-derived) AND by observing which IPs receive inbound port-53 queries. Also uses `ip_matches_target()` for CIDR support instead of exact string match.
- **Acknowledge/Dismiss state overwritten** — the detector was re-opening acknowledged and dismissed deviations on every cycle. Now only `resolved` (from Authorize) is re-opened on recurrence; acknowledged and dismissed states are durable.
- **`vlan_scope` deserialization warning** — `"__global__"` sentinel in database was being JSON-parsed every poll cycle, triggering spurious warnings. Now filtered before parsing.
- **Potential deadlock** — `futures::executor::block_on()` in legacy code path replaced with native async/await.
- **Behavior reset required double-click** — `window.confirm()` provided no feedback, so the first click appeared to do nothing. Replaced with an inline two-step flow: first click fetches and displays row counts per table, second click confirms the reset with full deletion summary.
- **Phantom SNMP interfaces on stackable switches** — Cisco SG550X and similar stackable switches pre-allocate interfaces for up to 8 stack units, creating hundreds of `ifOperStatus=6` (notPresent) ghost interfaces. Profiles with `skip_not_present` now filter these automatically.

### Added

- **VLAN column in deviations table** — policy page deviations table now shows VLAN name for each deviation.
- **First Seen column** — deviations table and investigation cards now show both First Seen and Last Seen timestamps.
- **Policy deviations in diagnostic report** — report now includes total, new, acknowledged, resolved, and DNS deviation counts.
- **"View in Policy" link** — investigation page deviation cards link back to the Policy page for resolution.
- **Dismissed status for deviations** — "Dismiss" action now sets a distinct `dismissed` status (previously mapped to `resolved`). Dismissed deviations are hidden from the default view.
- **Delete all deviations** — admin action to purge all policy deviations; also included in the full behavior engine reset.
- **Reset preview endpoint** — `GET /api/behavior/reset-preview` returns row counts per table without deleting, powering the new two-step reset UI.
- **Sidebar scrollbar** — sidebar content area is now scrollable on smaller screens; logo header and Settings footer stay pinned.

## [0.3.5] - 2026-03-26

### Added

- **SNMP profiles for HPE/Aruba and Cisco SMB switches** — Aruba 2540 (JL356A) and Cisco SG550X/SG350X/SG250X stackable switches now have dedicated profiles with proper interface naming, port classification, and hidden index filtering. Data contributed by [@robertbovens](https://github.com/robertbovens).
- **Auto-generated device ID** — primary router device ID is now slugified from the router's identity string (e.g., "MikroTik-ac2" → "mikrotik-ac2") instead of hardcoded "rb4011". Model auto-detected from `system/resource` board-name.
- **SNMP profile documentation** — `docs/snmp-profiles.md` explains profiles, generic fallback behavior, and how to contribute.

### Fixed

- **Legacy device ID migration** — existing installations with `device:rb4011:*` secrets are automatically migrated on startup. Secrets re-encrypted with new AAD in a single transaction. Rollback-safe, retries on failure.
- **Correlation engine silent fallback** — removed dangerous `unwrap_or("rb4011")` that could corrupt port identity data. Now skips cycle if no router found.
## [0.3.4] - 2026-03-25

### Security

- **SSRF DNS rebinding mitigation** — added `revalidate_host()` check immediately before client construction in add-device and test-connection handlers, closing the TOCTOU window between initial validation and connection.
- **SwOS response body cap** — `SwosClient::fetch()` now enforces 8MB body limit matching `MikrotikClient`, preventing OOM from compromised switches.
- **Device error sanitization** — device API endpoints no longer leak internal hostnames, certificate details, or file paths. Errors are classified into safe categories (`auth_failed`, `tls_error`, `connection_timeout`, etc.) and full details are logged server-side only.
- **Login rate limiter tracks IP** — brute-force protection now rate-limits by both username and client IP (via `X-Forwarded-For`/`X-Real-IP`), preventing username rotation attacks from a single source.

### Fixed

- **Policy deserialization warnings** — corrupt `authorized_targets` or `vlan_scope` JSON in policy rows now logs a warning instead of silently defaulting to empty, preventing silent policy changes from data corruption.
- **SwOS parse failure visibility** — `stats.b` and `vlan.b` parse failures upgraded from silent `debug` to `tracing::warn` with degraded status context.
- **WAN interface hardcoded** — `wan_interface` from `server.toml` was ignored in 4 places (traffic poller, traffic tracker, topology, policy sync), all hardcoded to `"1-WAN"` or `"ether1"`. Now reads from config everywhere.
- **Version endpoint** — `/health` now returns `version` field; startup log includes version. Set via `ION_DRIFT_VERSION` env var at build time (Dockerfile `--build-arg VERSION=...`).

### Added

- **SNMP profile collection script** — `scripts/snmp-profile-collect.sh` for users to collect switch OID data for building new vendor profiles. Automatically anonymizes MACs (OUI preserved), hostnames, and port descriptions.

## [0.3.3] - 2026-03-25

### Fixed

- **Response body cap too low** — bumped from 2MB to 8MB. RouterOS connection tracking tables on busy networks return 2.6-2.8MB responses, hitting the previous cap. Reported by [@robertbovens](https://github.com/robertbovens) in [#4](https://github.com/Cyber-Hive-Security/ion-drift/issues/4).

## [0.3.2] - 2026-03-25

### Security

- **HTTP response body cap** — `MikrotikClient` now enforces a 2MB response body limit, preventing OOM from misbehaving or compromised routers. New `ResponseTooLarge` error variant.
- **SNMP walk loop protection** — all 7 walk functions now check OID monotonicity (break if OID doesn't strictly advance) and enforce a 10,000-iteration safety cap, preventing infinite loops from buggy SNMP agents.
- **`record_page_view` requires admin** — POST `/api/stats/page-view` now uses `RequireAdmin` to satisfy the mutating-endpoint authz policy.

### Changed

- **`decode_hex_string` rewritten** — replaced manual UTF-8 state machine with `String::from_utf8_lossy()`, correctly handling 4-byte sequences and malformed input.
- **`encrypt_value()` helper** — extracted shared encryption helper in `SecretsManager`, eliminating 9 duplicated AES-256-GCM encrypt call sites across 4 functions.
- **`router.ca_cert_path`** now present (empty default) in `server.example.toml` instead of commented out.

### Fixed

- Test failures: added missing `port_index` field to `PortMetricEntry` test initializers, removed OIDC keys from required config example keys (OIDC section is intentionally commented out).

## [0.3.1] - 2026-03-25

### Fixed

- **[Security] Session secret fail-open** — secret decryption errors during startup were logged but ignored, leaving the service running with an empty HMAC session signing key. Decrypt errors are now fatal; `Ok(None)` generates an ephemeral random secret with a warning.
- **[Security] Env var migration on KEK mismatch** — decrypt errors (`Err`) were conflated with missing secrets (`Ok(None)`), allowing the env var credential migration path to trigger on KEK corruption and silently overwrite encrypted secrets. Decrypt errors now abort startup.
- **Router queue poller starvation** — low-priority pollers (`log_aggregation`, `behavior-fw-cache`) were permanently starved by steady high/normal-priority batches. Added age-based priority promotion: batches waiting >120s are promoted to High priority.
- **StatsStore blocking I/O** — `tokio::sync::Mutex` with synchronous rusqlite calls blocked Tokio worker threads during I/O and WAL checkpoints. Switched to `std::sync::Mutex` + `spawn_blocking`.
- **Starvation warning log flood** — poller starvation detection warned every queue loop iteration (thousands/minute). Now warns once per threshold crossing.

### Changed

- Secret decryption failures during startup now produce explicit error messages identifying the failing secret and suggesting root cause (KEK mismatch, missing `machine.key`), instead of silently falling through to "Authentication failed" from the router.

## [0.3.0] - 2026-03-24

### Added

- **Router request queue** — all background poller API requests are serialized through a centralized queue, preventing concurrent TLS sessions from overwhelming low-end routers (hAP ac², RB750). Features priority scheduling (High/Normal/Low), batch submission, deduplication, adaptive gap control, circuit breaker, and starvation detection.
- **Configurable poll intervals** — new `[polling]` config section with `queue_gap_secs`, `traffic_interval_secs`, `metrics_interval_secs`, `connection_interval_secs`, `behavior_interval_secs`, `correlation_interval_secs`, `topology_interval_secs`, `policy_sync_interval_secs`. All have sensible defaults; increase for low-end devices.
- **In-app restart** — when primary router connection settings change, a modal offers "Restart Now" (triggers graceful process exit, Docker restarts automatically) or "I'll do it later". New `POST /api/system/restart` endpoint (admin-only).
- **Env var credential migration** — `DRIFT_ROUTER_PASSWORD` is now automatically migrated to the encrypted secrets DB on first run. Remove the env var from compose after initial setup.
- **Auto-detect CA cert** — mounts at `/app/certs/root_ca.crt` are auto-detected without requiring `ca_cert_path` in config (convention over configuration).
- **Bundled default config** — Docker image includes a default `server.toml` so `docker compose up -d` works without any config file for public CA (Let's Encrypt) users.
- **Setup wizard "Access Ion Drift" button** — setup complete page now has a link to the login page.
- First-run walkthrough in docs, troubleshooting guide, expanded Quick Start.

### Changed

- Default `secure = false` for session cookies — most first-time users access over HTTP. Set `true` when behind HTTPS reverse proxy.
- Default traffic poll interval increased from 10s to 30s; connection poll from 30s to 60s; correlation from 60s to 120s.
- Primary router credential updates now save before returning restart-required (previously blocked the save entirely with a 409).
- Device edit form only sends changed connection fields — editing name/model no longer triggers restart warning or requires re-entering credentials.
- Removed nmap and libcap2-bin from Docker image (nmap scanning was removed in v0.2.4).
- Removed `cap_add: NET_RAW/NET_ADMIN` from docker-compose.example.yml.

### Fixed

- **Login page redirect loop** — `usePageTracking` fired unauthenticated API calls causing 401 → full page reload loop on login screen.
- **Credential persistence** — env var router password was never migrated to encrypted DB in local auth mode; removing the env var caused auth failure.
- **CA cert permissions** — bind-mounted certs at `/app/certs/` were unreadable by the container's app user; entrypoint now copies to `/app/data/certs/` with correct ownership.
- **Device edit disabled without credentials** — save button required username field even for non-credential changes.
- **React hooks ordering error** — `useState` for edit state was after early return, causing "Rendered fewer hooks than expected" crash on settings page.
- Hostname/SAN mismatch documented in troubleshooting (connecting by IP when cert is issued for hostname).

### Security

- `POST /api/system/restart` requires `RequireAdmin` — only admin users can trigger restart.

## [0.2.4] - 2026-03-23

### Added

- **DNS policy deviation detection with MITRE ATT&CK context [beta]** — cross-references connection tracking with infrastructure policy map to detect unauthorized DNS servers; enriched with ATT&CK technique mappings (T1071.004, T1568, T1048.003, T1583.001); resolve actions (authorize, deny_all, dismiss, acknowledge) create policies organically from observed traffic
- Policy deviations dashboard card, investigation page cards with clickable ATT&CK pills, and policy page deviations table with inline resolve
- Statistics page with page view tracking (90-day retention) and diagnostic report generation
- Diagnostic report: environment info, scale metrics, feature adoption, engine health, inference stats, anomaly dispositions, page views
- Investigation page enrichment: device context card (manufacturer, type, VLAN, switch port, link speed), traffic context (1h/24h bandwidth vs baseline), GeoIP on destinations
- Graceful startup when router is unreachable — web UI starts so credentials can be fixed via Settings > Devices instead of requiring filesystem access
- OIDC without mTLS bootstrap: KEK derived from OIDC client secret via argon2id (no env vars needed after first run)
- Environment variables optional after first run for all auth modes (local, OIDC, mTLS bootstrap)
- Security model comparison in auth docs with threat scenario matrix
- HTTP compression (gzip + Brotli) via tower-http
- Immutable cache headers for content-hashed static assets
- VLAN metrics downsampling (SQL-level bucketing reduces response size ~12x)
- Single primary router enforcement with infrastructure fallback dialog

### Fixed

- SNMP v2c community string wrapped in SecretString (was plain String; v3 passwords already wrapped)
- KEK salt now random and persistent per installation (was deterministic from filesystem path)
- OIDC client secret restored from encrypted DB on cached-KEK startup (was left empty, breaking OIDC login after restart)
- Resolved/acknowledged policy deviations re-open when the same violation recurs
- Authorize resolve action merges targets into existing VLAN policy instead of replacing (prevents silent allowlist clobbering)
- DNS deviation detector skips DNS servers (their outbound port-53 is recursive resolution, not a violation)
- DNS deviation query groups by all identity columns (was nondeterministic with MAX on ungrouped columns)
- Authorize merge excludes global policies from VLAN-scoped writes (prevents stale global copies)
- Task supervisor catches synchronous panics in factory calls (not just async future panics)
- Backoff jitter (±25%) in task supervisor to prevent thundering herd
- SNMP poll cycle rejected entirely on partial ifName walk failure (prevents mixed name sets)
- Replaced serde_json unwrap() with unwrap_or_default() in 8 route handlers
- Added LIMIT 10000 safety bounds to unbounded neighbor/backbone queries
- Invalid deviation resolve action returns 400 instead of 200
- Removed dead nmap scanning code (521-line page, types, hooks)
- IANA ifType magic numbers replaced with named constants

### Changed

- "Legacy mode" renamed to "OIDC without mTLS bootstrap" in all docs
- Config docs clarify credentials are managed via setup wizard, not env vars
- Router port docs warn against 8728/8729 (proprietary API, not REST)
- Docker Compose example includes credential management comment
- Default router username in server.example.toml changed from "admin" to "ion-drift"
- License display: "1 Router (full NDR) · Unlimited infrastructure devices"
- Frontend queries split from monolithic queries.ts into 9 domain modules
- Commented-out future vendor profile code removed from snmp_profile.rs

### Security

- Router user permissions docs: default to read-only, write only for provisioning
- TLS requirements documented: supported signature algorithms (ECDSA-SHA256/384, RSA, Ed25519), ECDSA-SHA512 not supported
- Docker container resource limits (2 CPU, 2GB RAM) in compose files
- Warning logged when router password is empty after all loading stages

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
