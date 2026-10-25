# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.5.6] - 2026-10-24

Maintenance release: no feature changes. User-visible changes are limited to the eight items under Fixed below.

### Security

- `tokio` 1.52.3 → 1.54.1 (RUSTSEC-2026-0386, `AsyncFd` I/O safety). RUSTSEC-2026-0387 (`crypto-bigint` timing) is recorded as ignored in `deny.toml`: the crate is reached only through `openidconnect` for verifying ID-token signatures with the IdP's public keys, and the fixed version is not reachable without an `openidconnect` major bump.
- Module findings published on the in-process event bus now carry the same clamped content the store holds. Before, the raw submission was published and a bus consumer stored it a second time under the module name `in-process`, with unsanitized references. That consumer is gone; the inbound endpoint is the single persistence point.

### Changed

- **Clippy at zero, blocking in CI.** 300 unique warnings cleared across the workspace: nested `if`s collapsed into
  let-chains, dead code removed, remaining `too_many_arguments`/`result_large_err` cases carry an item-level allow with
  a one-line reason. The CI job now runs `cargo clippy --workspace --locked --all-targets -- -D warnings`.
- **ESLint for the web app.** ESLint 9 flat config (typescript-eslint, react-hooks, jsx-a11y) added and run in CI.
  Form labels are associated with their controls, clickable rows and cards are keyboard reachable (including every data-table row, which now takes focus and expands on Enter or Space), and `autoFocus`
  stays only where a field opens on user action.
- **SonarQube findings resolved.** `Number.isNaN`/`Number.parseInt` throughout; three regexes with super-linear
  backtracking rewritten (Cisco port names, trailing port numbers, uptime) with tests; the setup-wizard retry and the
  secret editor no longer drop promise rejections, and the secret editor shows a save error. Default string sorts and
  the decorative `Math.random()` star field were reviewed and left as-is (see KNOWN_ISSUES).
- **Internal identifiers removed.** Lab addresses, hostnames, and user paths in tests, the example config, UI
  placeholders, and docs replaced with RFC 1918 and RFC 5737 example ranges and `example.com`.
  `scripts/check-internal-identifiers.sh` runs in pre-commit and CI, scans staged content, and fails closed.
- `ROADMAP.md` rewritten for the standalone Drift 1.0 train (0.5.7 to 1.0); companion-product work moved to post-1.0.

### Fixed

- **Switch port grid showed the bridge as port 1.** RouterOS lists the bridge interface itself as a tagged member of the management VLAN, and the switch poller recorded it as a VLAN member like any port. On a switch whose bridge is named `bridge1`, the port grid read the trailing digit as port 1 and drew it over ether1. The poller no longer records the bridge itself as a VLAN member, so it disappears from the port grid and the VLAN audit grid; bonds and other bridge members are unaffected. Existing rows clear on the first poll after upgrade. The Port Traffic table on the same page now lists physical ports only; bridge and VLAN interfaces, which have no port metrics, no longer appear as ports marked Down.
- **Advisory findings showed no device.** CVE, exposure, and exploitation findings are about a specific router or switch, but the finding model could only name endpoints by MAC, so the Devices column stayed empty and findings for three switches looked like duplicates. Findings now carry a typed `subjects` list (an open `kind` plus `id`; Drift renders `device` by registry id, `endpoint` by MAC, and `domain` by name, and shows any other kind as text); the Findings page shows each subject by name, linking switches to their detail page. Lookalike-domain findings name the domain. `device_macs` remains in the module API and the HTTP API as a deprecated endpoint-only view. This bumps findings.db to schema version 2 with existing rows backfilled; rolling back to 0.5.5 afterwards requires the pre-upgrade backup.
- **CVE and advisory links were plain text.** Findings now carry a `references` list of URLs; CVE findings reference their NVD entry, exposure and exploitation findings reference the advisory's sources, and the Findings detail panel shows them as links. The `Details: https://...` line is gone from CVE recommended actions. Module-supplied references are kept only when they are well-formed `http`/`https` URLs, and every finding's final reference list passes through the same check at emission, so advisory rows stored by earlier versions cannot carry an unchecked URL onto the page. This bumps findings.db to schema version 3 (column added, no backfill); rolling back to 0.5.5 afterwards requires the pre-upgrade backup.
- **Devices with few distinct flows never finished learning.** Cameras, thermostats, and single-purpose servers could stay in `learning` indefinitely: promotion required ten distinct flow tuples, and the 3-day extension repeated without limit. Graduation now measures coverage (days seen in the last 7) and stability (no flow tuple first seen in the retained 30-day history within the last 48 hours, so a flow that recurs weekly does not count as new), sparse devices are re-evaluated every pass, a device is marked baselined only after its baseline has been computed, and the profile records both values (`days_seen`, `last_new_flow`, added to `device_profiles` automatically on first start). The Learning Until cell on the Behavior page shows them on hover. On first start after upgrading, devices the old rule had stuck in learning or sparse are re-evaluated and may graduate in bulk within ten minutes. This bumps behavior.db to schema version 2; rolling back to 0.5.5 afterwards requires the pre-upgrade backup.
- The secret editor on the Security settings page now shows a save error instead of silently dropping the rejection.
- Uptime strings are parsed from the start of the string (`formatUptime`); RouterOS always supplies a bare uptime, so output is unchanged for real data.
- `TempDir::into_path` deprecation in storage tests; `cfg(fuzzing)` declared as a known cfg in `mikrotik-core`.
- `modules_registry` re-exports restored after an over-eager auto-fix; the bin target does not use them, so the
  unused-import lint is silenced there with a comment.

## [0.5.5] - 2026-10-22

### Security

- **Compromised eMudhra intermediates rejected.** Updated `rustls-webpki` to 0.103.16, which rejects any certificate
  path containing the eight emSign intermediates whose private keys are now public, including paths through
  Sectigo's cross-signature that 0.5.4's root-store update could not block (RUSTSEC-2026-0382).
- **rustls 0.23.46.** Fixes RUSTSEC-2026-0346 (session secrets in `Debug` output), RUSTSEC-2026-0347 (ECH rejection
  data ordering), RUSTSEC-2026-0348 (Brotli certificate decompression allocation) and RUSTSEC-2026-0349 (key-share
  prediction downgrade). Drift does not enable ECH or the `brotli` feature or log session values, so the practical
  exposure was limited to the key-share downgrade.
- Replaced yanked `chacha20` 0.10.0 with 0.10.2.
- **Web UI dependency `seroval` 1.7.0** (critical: GHSA-mv8w-475r-vwqw, GHSA-p6vx-979v-rg4c, GHSA-jp82-f5mq-hwhp),
  pulled in by the router library and shipped in the browser bundle. Build and test tooling (vite, vitest, postcss
  and others) also updated; those never ship.
- `quinn-proto` 0.11.19 (RUSTSEC-2026-0338 to 0342). It was listed in the lockfile but never compiled into Drift.

## [0.5.4] - 2026-10-22

### Security

- **eMudhra CA distrust.** Updated the bundled public root store (`webpki-roots` 1.0.7 → 1.0.10), which removes
  "emSign ECC Root CA - G3". That root signed eight eMudhra intermediates whose private keys were found to be
  recoverable (disclosed 2026-10-17; distrusted by Mozilla, Chrome, Apple and Microsoft). Affects Drift's outbound
  HTTPS and SMTP connections. Intermediates reachable through Sectigo's cross-signature are blocked in 0.5.5.

## [0.5.3] - 2026-09-25

### Added

- **Vulnerability feed.** Daily NVD + CISA KEV pull for RouterOS. Every managed RouterOS device whose version
  falls in a published affected range gets a finding; CVEs CISA lists as exploited in the wild are Critical.
  Findings state plainly that Drift checked the version, not whether the affected feature is enabled.
- **Mandatory feed consent.** Administrators confirm the feed (on by default) or turn it off, with a warning,
  before any outbound request is made. Settings → Security shows who decided and when. Turning the feed off
  stops downloads: checks continue against the vulnerability data last downloaded (if any), but newly
  published or newly exploited RouterOS vulnerabilities are not learned.
- **Vulnerability escalation reopens.** An acknowledged vulnerability finding reopens, with a note naming the
  old and new severity, when it escalates — for example when CISA lists the CVE as actively exploited.
- **Service exposure findings.** Bundled advisories scoped to a service (CVE-2026-16347: `api`/`api-ssl`)
  now raise an early-warning finding when the service is enabled — High when reachable from anywhere, Low
  when restricted by `address` — without waiting for an attack. An acknowledged finding reopens if the
  restriction is later removed.
- **Operator resolutions stick.** A vulnerability or exposure finding an operator resolves manually stays
  resolved. Drift reopens only findings it resolved itself — after an upgrade, if the version regresses;
  after a service is disabled, if it is re-enabled.
- **Feed health.** Findings shows a banner when the feed is off (stating the date of the data still being
  checked), or when a feed source has not succeeded in three days or has never succeeded after being attempted.

### Changed

- Advisory catalog `version_constraint` must now be `null` or an array of version ranges.

### Fixed

- **Graceful degradation when the router is unreachable.** Connections, Logs, ARP, DHCP leases, pool
  utilization, firewall filter, and network-map status now serve the last-known data with a
  "showing last-known data" banner instead of returning a 502 error.

### Security

- Ship `session.secure = true` in the production config template, and warn at startup when session
  cookies are configured without `Secure` on a non-loopback bind. (The Secure flag governs only the
  browser-to-proxy leg, which is HTTPS.)
- Stop forwarding `X-Forwarded-*`, `X-Real-IP`, and `Forwarded` headers to modules through the
  reverse proxy: a registered module no longer receives the client's real IP or internal topology.
- Strip control and bidirectional-override characters from module-published finding content before
  storage.
- Send a versionless `User-Agent` on outbound requests to modules.
- Return a generic `400` from `/auth/callback` on a malformed request instead of a framework error
  that names the missing query fields.
- Escape `baseline_status` in the topology tooltip before it is rendered.

### Internal

- Abstract the router client behind a `RouterApi` trait and add end-to-end handler tests for the
  degradation paths. No behavior change.

## [0.5.2b] - 2026-07-23

### Fixed

Follow-ups from the v0.5.2a release smoke test (no functional blockers were
found; these are polish/UX):

- **Module registration errors are human-readable** — "could not reach module
  at \<url\>" / timeout / HTTP-status / invalid-manifest messages instead of the
  raw `GET <url>/manifest` request string. Still no transport internals.
- **Module registration form validates inline** — persistent per-field errors
  for URL / shared secret / API token instead of native browser tooltips; no
  request fires while invalid.
- **`/modules` redirects to `/admin/modules`** instead of 404ing.
- **Statistics daily page-view chart no longer hides "today"** — date labels
  were parsed as UTC midnight and rendered one day early in negative-offset
  timezones; the current day's bar existed but was mislabeled as yesterday.

## [0.5.2a] - 2026-07-23

### Fixed

- **Settings → System "About" showed no version** — the 0.5.2 hardening pass
  removed the build version from unauthenticated `/health` but never added the
  promised authenticated replacement, so the About panel rendered "—". New
  authenticated `GET /api/system/about` endpoint now serves the version to
  logged-in operators; `/health` stays version-free.

## [0.5.2] - 2026-07-23

### Security

Pre-release security-hardening pass (findings from an internal review + an OWASP
WSTG coverage assessment). No known exploitable pre-auth RCE, SQL injection,
command injection, or secret disclosure was found; the changes below close
lower-severity gaps and add defense-in-depth.

- **SSRF guard unified and hardened.** Module-registration and device-connection
  outbound requests now share one guard that additionally blocks IPv6-embedded
  IPv4 forms of link-local/metadata addresses (`::ffff:`, NAT64, IPv4-compatible),
  disables HTTP redirect following, and re-validates the host before every probe
  (not just at registration). RFC1918/ULA LAN targets remain allowed by design.
- **OIDC login-CSRF / session-fixation fixed.** The in-progress login flow is now
  bound to the initiating browser via a short-lived state cookie verified in the
  callback (PKCE + nonce already prevented token injection).
- **CSRF guard tightened.** The `application/json` requirement now applies to
  *every* mutating request, including no-body ones (previously bypassable).
- **HTTP security headers added:** HSTS, Referrer-Policy, Permissions-Policy (now
  also applied to the setup wizard).
- **Login username-enumeration timing** closed (constant-time argon2 path on
  unknown users).
- **Session hardening:** optional idle/inactivity timeout
  (`session.idle_timeout_seconds`); startup warnings for `secure=false` /
  `same_site="none"`.
- **Rate-limit IP spoofing:** new `server.trust_proxy_headers` (default `true`);
  set `false` when directly exposed so `X-Forwarded-For` can't rotate the per-IP
  bucket.
- **Output hardening:** device errors and RouterOS log fields are sanitized before
  reaching clients; `/health` no longer discloses the build version to
  unauthenticated callers; a provisioning error is now generic.
- **Module trust boundary:** inbound module-supplied finding content is
  size-clamped; the replay-nonce cache is bounded (periodic GC + hard cap); the
  unauthenticated syslog ingest is rate-capped.
- **Crypto/config:** license verification uses Ed25519 `verify_strict`;
  `--dump-config` recursively redacts secret-looking keys (incl. the `[modules]`
  table); constant-time comparison for the setup bootstrap token; startup warning
  when the RouterOS API is configured over plaintext HTTP.
- Added `subtle` for constant-time comparisons.

Second hardening pass (external review). Follow-up fixes verified against the
codebase and covered by unit tests:

- **Module proxy locked to API-only.** The `/api/modules/<name>` reverse proxy now
  enforces the manifest's `exposed_routes` allow-list (only declared method/path
  pairs are forwarded; declared paths match their own sub-paths but not arbitrary
  ones) and forces inert responses (overrides `Content-Type` to `application/json`
  + `nosniff` + `attachment`), so a registered module can never serve active
  content on Ion Drift's authenticated origin.
- **SSRF: proxy revalidation + strict device-host parsing.** The live module proxy
  re-runs the SSRF guard before every request (not just at registration), closing
  a post-registration DNS-rebinding path. Device hosts must now parse as a bare IP
  literal or `url::Host`, rejecting userinfo/path/fragment/scheme/port smuggling
  (e.g. `x@169.254.169.254/latest/meta-data/#`) that previously bypassed the guard
  via a validator/connector parser differential.
- **Login DoS hardening.** Rate-limit slots are reserved *before* password
  verification (a burst can no longer all be admitted); Argon2 now runs on a
  blocking thread with the secrets-DB lock released first (no more serializing the
  DB behind hashing); a global semaphore bounds concurrent verifications. When no
  trusted proxy is configured the limiter keys on the real socket peer IP instead
  of a shared bucket.
- **OIDC pending-state** entries are expired before the capacity check, so a burst
  of abandoned login-starts can't lock out new logins for the cleanup interval.
- **Session tokens stored hashed.** The `sessions` table and in-memory map are now
  keyed by `SHA-256(token)`; the bearer token lives only in the client cookie, so
  a stolen `sessions.db`/backup can't be replayed. (Invalidates existing sessions
  on upgrade — users re-authenticate once.)
- **Module inbound ingest bounds.** Publish authorization is checked before the
  nonce is recorded (an unauthorized kind can't consume cache); envelope
  `nonce`/`event_id` lengths and previously-unclamped nested finding JSON
  (`metadata`, custom-evidence payloads) are now bounded.
- **Event dispatcher bounded.** Concurrent deliveries are capped by a semaphore
  (excess shed, not queued), the configured per-attempt `request_timeout` is now
  actually applied, and the circuit breaker is re-checked between retries.
- **Response size caps.** RouterOS/SwOS clients and the module proxy stream
  responses with an early `Content-Length` reject and a mid-stream cap, instead of
  buffering the whole body before checking; the SwOS pre-auth 401 body drain is
  bounded.

See `SECURITY.md` for the deployment guidance and known-limitations/roadmap items
(local-account MFA, password rotation, multi-user roles, KEK-off-volume, syslog
authenticated transport, SSRF socket-layer IP pinning) surfaced by the reviews.

### Fixed

- **UTF-8 panic** in the RouterOS client's deserialize-error preview (`&body[..200]`
  could split a multibyte char and panic the poll task); now truncates on a char
  boundary.
- **mTLS/CertWarden setup wizard** was unsubmittable — the form was missing its
  `setup_token` input, so every browser submit failed "Invalid setup token".
- **204 responses** (e.g. page-view tracking) no longer make the frontend API
  client throw on an empty body.
- **Weekly snapshots** now persist real ISO period boundaries instead of
  placeholder strings (`2026-W09-start`).

### Dependencies

- **quinn-proto 0.11.16** — fixes RUSTSEC-2026-0185 (high, 7.5): remote memory
  exhaustion from unbounded out-of-order QUIC stream reassembly (transitive via
  hickory's QUIC feature). Also replaces the yanked `spin` 0.9.8 with 0.9.9.

## [0.5.1] - 2026-06-09

### Fixed

- **World map / GeoIP empty on existing installs** (#6) — Docker named volumes are only seeded from the image on first creation, so any install whose data volume predates the GeoIP bundling shadowed the bundled DB-IP files forever. Bundled databases now live at `/app/seed/geoip` (outside the volume mount) and the entrypoint idempotently seeds them into the data volume on every start. Also: a GeoIP download failure during image build now fails the build instead of silently shipping an empty database.
- **Release workflow tag triggers** — `drift-v*` tags now build and publish the Docker image (the `drift-v0.5.0` tag did not match the previous `v*`-only trigger), and `:latest` is updated on release tags.

### Added

- **CI workflow** — `cargo test --workspace`, frontend typecheck and build on every push/PR to `main`/`development`.

## [0.5.0] - 2026-04-10

### Added

- **Module API v1.0** — stable plugin contract for extending Drift core with custom modules. Two new workspace crates: `ion-drift-module-api` (1.0.0, path-only, the stable trait/type contract) and `ion-drift-module-host` (runtime registry, event bus, storage backend, panic guard). Single `Module` trait with native `async fn` and an `ErasedModule` adapter for dyn-compat. See [docs/module-developer-guide.md](docs/module-developer-guide.md).
- **Capability-scoped module runtime** — modules declare a `Capabilities` struct (storage, events, state reads, secrets); the host builds a `ModuleContext` whose handles correspond exactly to declared capabilities. Undeclared state reads return `None`; undeclared events return `EventError::NotDeclared`.
- **Per-kind event channels** — `tokio::sync::broadcast` per `EventKind` with internal forwarder tasks merging into a unified `EventReceiver::recv()` API. High-rate topics cannot lag low-rate subscribers.
- **Host-stamped event provenance** — `DriftEvent::ModuleCustom` events have their `source` field populated by the host from the publishing module's actual name. The plain `publish()` rejects `ModuleCustom`; modules must use `publish_custom(kind, payload)`. Prevents spoofing.
- **Namespace-scoped module secrets** — declared secret names must start with `MODULE_<UPPER_NAME>_*`. Modules attempting to declare names outside their prefix are rejected at registration, preventing exfiltration of Drift core secrets.
- **Isolated SQLite per module** — each module that declares `StorageNeed::Isolated` gets its own file at `${data_dir}/modules/<name>.db`. Module-owned schema and migrations, tracked in a `__migrations` metadata table. All writes run through `tokio::task::spawn_blocking`.
- **Panic-isolated module lifecycle** — `Module::init` and `Module::shutdown` are wrapped in `catch_unwind`. Module HTTP handlers are wrapped in a tower panic guard that returns HTTP 500. A misbehaving module is marked `Disabled` and Drift continues running.
- **Module test harness** — `MockContextBuilder` plus `MockBehaviorRead`, `MockSwitchRead`, `MockConnectionRead`, `MockSnapshotRead`, `MockDeviceManagerRead`. Module authors can unit-test in isolation by enabling the `testing` feature on `ion-drift-module-api`.
- **Module registry endpoint** — `GET /api/system/modules` returns the list of loaded modules with name, version, API version, status, and reason. Authenticated route.
- **Per-device router queue** — RouterOS managed switches now each get their own `RouterQueue` instance, serializing all API calls through a single connection per device. Fixes CRS326 crashes caused by 80+ accumulated REST sessions from concurrent `tokio::join!` polling. Extended `QueuedRequest` with POST support.
- **Inline VLAN anomalies** — clicking a VLAN row showing anomalies on the Investigation page now renders them in a red-bordered section with severity badge, type, device MAC, and time-ago; clicking drills into the device trace.

### Changed

- **Engine consolidation (Phase 1)** — extracted shared identity helpers into `identity_utils.rs` (`is_infrastructure_type`, `identity_overrides_lldp`); removed duplicates from `correlation_engine.rs` and `topology.rs`. Removed `SpikeCandidates` empty placeholder and 3 hardcoded MAC debug trace blocks.
- **Engine consolidation (Phase 2)** — consolidated `DeviceResolutionMaps`: removed the duplicate struct from `topology_inference/graph.rs`; `InfrastructureGraph::build` now takes two `&HashMap` params directly.
- **Engine consolidation (Phase 3)** — alerting SQL moved to the storage crate: new `ion-drift-storage/src/alerting.rs` with 14 `SwitchStore` methods replacing raw `store.db()` free functions. Alert types now live in the storage crate.
- **Event payload versioning** — `DriftEvent` is `#[non_exhaustive]`, payload structs are suffixed `V1` (with `V2` etc. for additive changes), so adding fields or variants is a minor bump.
- **`ApiVersion::CURRENT`** — now computed from `CARGO_PKG_VERSION_MAJOR`/`MINOR` at compile time via a `const fn` parser. Will no longer drift from Cargo.toml.
- **Module listing at startup** — host logs loaded module list (count + names) after `ModuleRegistry::load`, so operators can tell at a glance which modules a binary was built with.

### Fixed

- **Auth bypass on `/api/system/modules` and `/api/modules/*`** — module routes were nested onto the outer router AFTER `api_routes` middleware was applied. Moved inside `api_routes` BEFORE the auth/CSRF/demo-sanitize layer stack. Listing route now uses the `RequireAuth` extractor.
- **Module `init`/`shutdown` panic escapes** — previously a `panic!` inside a module's lifecycle propagated up and crashed Drift. Now wrapped in `AssertUnwindSafe + catch_unwind`; panicking modules are marked `Disabled` with the panic message and Drift continues running.
- **SQLite blocking the Tokio runtime** — `SqliteBackend::write_any` held an `async` mutex and ran `rusqlite` calls inline on worker threads. Now uses `std::sync::Mutex` + `tokio::task::spawn_blocking` for all queries and migrations.
- **Event bus noisy-neighbor lag** — single broadcast channel + client-side filtering meant a high-rate topic could advance the channel head past a low-rate topic, causing low-rate subscribers to miss events. Per-kind channels eliminate the cross-topic lag path.
- **Nullable VLAN in `read_traits::recent_anomalies`** — `row.get::<_, i64>(4)` returned a rusqlite error on SQL NULL. Fixed to `Option<i64>`.
- **Shutdown signal wiring** — `ModuleRegistry::shutdown_all` existed but was never called; `module_shutdown.cancel()` was never triggered. Drift now wires these into the SIGTERM path via `axum::serve.with_graceful_shutdown` with a 5-second bounded timeout.
- **`MockContextBuilder::with_secret`** — secrets were stored in the mock resolver but `declared_secret_names` was hardcoded to empty, so `SecretsHandle::resolve` always returned `None` and the test harness silently lied.

### Removed

- **`Module::health`, `HealthEndpoint`, `MetricsCollector`, `MetricsHandle`** — dropped from the v1.0 contract per YAGNI. They were placeholder shapes with no host implementation; freezing them into a stable contract would have created a semver trap. Health and metrics will return as additive minor bumps in 1.x once the host has a real implementation.
- **Unenforced capability bools** — `routes`, `tasks`, `health`, `metrics` flags removed from `Capabilities`. The host never checked them. Final shape: `storage`, `events`, `state_reads`, `secrets` — every field corresponds to something the host actually grants or denies.

## [0.4.0] - 2026-04-03

### Added

- **Resolved Infrastructure Snapshot** — new `infrastructure_snapshot.rs` introduces `ResolvedInfrastructureSnapshot` with versioned schema, evidence chains, conflict state, and SoA authority hierarchy. The correlation engine now produces and publishes snapshots after each cycle.
- **Unified LLDP device resolver** — new `device_resolution.rs` replaces 3 independent LLDP-to-device resolution implementations with a single shared resolver. 6-step precedence: exact match, RouterOS lookup, fuzzy match, IP match, MAC match, learned match. Learning with guardrails prevents phantom entries.
- **Provisioning permission pre-check** — queries RouterOS user/group before attempting provisioning. Shows setup commands if write permission is missing, instead of failing with cryptic errors.
- **Dual-threshold baseline promotion** — behavior engine now uses tiered promotion: fast-track at 5000+ observations, normal at 7 days + 200 observations, sparse mode at <50 observations, extended learning for borderline cases.
- **OUI device type mappings** — added ASRock, Maxtang, AZW, FN-LINK, Winstars, Super Micro Computer, Xensource (VMs), REALTEK SEMICONDUCTOR, CLOUD NETWORK TECHNOLOGY, Ugreen, NetApp.
- **Baselined endpoint icons** — baselined endpoints with a known device type now render as device icons instead of hexagons. Visual progression: hexagon = learning/unknown, icon = baselined + typed.
- **Router setup guide** — `docs/router-setup.md` covers MNDP configuration, API user setup, and provisioning overview.
- **USE-AGREEMENT v2.0** — 60-day satisfaction guarantee, dispute resolution, full provisioning disclosure (mangle + syslog + firewall log rules).

### Changed

- **Topology builder consumes snapshot** — topology.rs no longer performs its own LLDP resolution. It consumes the `ResolvedInfrastructureSnapshot` published by the correlation engine, reducing topology.rs from 1,661 to 1,133 lines (-528 lines deleted).
- **Snapshot readiness gate replaces startup delay** — removed the 120-second startup delay. Topology builder now waits for the first valid snapshot from the correlation engine before producing topology.
- **Shadow validation** — snapshot-driven topology ran in shadow mode for 86+ cycles before cutover, validating output parity with the old implementation.
- **Neighbor pruning** — stale MNDP entries are pruned after a 4-hour TTL, preventing ghost neighbors from persisting indefinitely.
- **BFS depth uses backbone links only** — adjacency calculation now uses backbone links only. MNDP on management VLAN previously created false direct paths between non-adjacent devices.
- **Binding priority refinement** — backbone trunks assigned low priority; classified trunks and multi-VLAN access ports assigned high priority.
- **Inference pre-population** — inference binding results now pre-populate the identity builder, ensuring stale bindings are overwritten instead of persisting.
- **Switch-local MAC filtering** — switch interface MACs are now filtered out, preventing them from appearing as phantom endpoint nodes in the topology.

### Fixed

- **Syslog provisioning: invalid field** — `bsd-syslog` field doesn't exist in RouterOS. Changed to `remote-log-format: syslog`.
- **Syslog action name: invalid characters** — RouterOS only allows alphanumeric characters in action names. Changed from `ion-drift` to `iondrift`.
- **`remote_port` deserialization** — RouterOS returns port as a string. Added `ros_u32_opt` deserializer to handle string-to-integer conversion.
- **`src-address` must be IP** — syslog provisioning was sending a hostname for `src-address`; RouterOS requires an IP address.

## [0.3.8]

### Added

- **Bundled DB-IP Lite GeoIP databases** — Docker image now includes DB-IP Lite City and ASN databases for out-of-box GeoIP support. World map, country summaries, and deviation enrichment (org names) work immediately without a MaxMind account. MaxMind GeoLite2 takes priority if the user provides their own files.
- **GeoIP source indicator** — Settings → System → GeoIP section now shows which database source is active ("MaxMind GeoLite2" or "DB-IP Lite") with appropriate attribution text.
- **DB-IP attribution** — CC BY 4.0 license attribution displayed in the GeoIP settings section when DB-IP Lite is the active source.
- **Source of Authority (SoA) model** — `DataClassification` (Authoritative, Observed, Inferred) and `SourceTier` (Router, RosSwitch, SwosSnmp, MultiSignal, Admin) enums enforced at the Rust type level. Every deviation carries its classification and provenance.
- **Structured service metadata on deviations** — `service`, `protocol`, `port`, `policy_id`, `classification`, and `observed_from` columns added to `policy_deviations` table. Existing deviations backfilled from deviation_type prefix on startup.
- **Policy lineage** — `policy_id` links each deviation to the infrastructure policy that defined "authorized," preserving traceability to T1 (Router) policy intent.
- **Policy editor documentation** — `docs/policy-editor.md` covers policy creation, resolve actions, admin policy protection, per-VLAN severity, CSV export, and ATT&CK mappings.

### Changed

- **GeoIP provider fallback chain** — `MaxMind GeoLite2 → DB-IP Lite → none`. The provider loads the first available database set from the geoip directory, preferring MaxMind if both exist.
- **Resolve handler reads from columns** — removed the temporary string-prefix shim (`dns_* → udp/53`). Service, protocol, and port are now read directly from the deviation record.

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
