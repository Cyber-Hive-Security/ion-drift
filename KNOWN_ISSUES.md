# Known Issues

Tracked issues from external code reviews and internal testing.

## Resolved

### [HIGH] Session Secret Fail-Open on Decrypt Error (main.rs)
**Source:** External security review 2026-03-25
**Fixed:** v0.3.1

Secret decryption errors were logged but startup continued with an empty session secret, creating a fail-open path where sessions were signed with a predictable empty HMAC key. Fixed by making decrypt errors fatal (`anyhow::bail!`) and generating an ephemeral random secret on `Ok(None)`.

### [HIGH] Err/Ok(None) Conflation in Secret Loading (main.rs)
**Source:** External security review 2026-03-25
**Fixed:** v0.3.1

Decrypt errors (`Err`) and missing secrets (`Ok(None)`) were both treated as "secret not found", allowing the env var migration path to trigger on KEK corruption. Fixed by making `Err` fatal and only allowing migration on `Ok(None)`.

### [HIGH] Router Queue Poller Starvation
**Source:** Internal testing 2026-03-25
**Fixed:** v0.3.1

Low-priority pollers (`log_aggregation`, `behavior-fw-cache`) were permanently starved by a steady stream of higher-priority batches. Fixed with age-based priority promotion (batches waiting >120s promoted to High priority) and reduced starvation log noise (warn once per threshold crossing instead of every loop iteration).

### [HIGH] Blocking SQLite I/O in StatsStore (stats_store.rs)
**Source:** External review 2026-03-25
**Fixed:** v0.3.1

StatsStore used `tokio::sync::Mutex` with synchronous rusqlite calls, blocking Tokio worker threads during I/O and WAL checkpoints. Fixed by switching to `std::sync::Mutex` + `spawn_blocking` for all database operations.

### [HIGH] Uncaught Synchronous Panic in Task Supervisor (task_supervisor.rs)
**Source:** External review 2026-03-25
**Status:** Already fixed prior to review

The factory function call is wrapped in `std::panic::catch_unwind` (lines 121-130). The reviewer was working from an older snapshot.

### [HIGH] Unbounded HTTP Response Body (client.rs)
**Source:** External security review 2026-03-25
**Fixed:** v0.3.2

`MikrotikClient::handle_response()` read entire response body into memory without a size limit. Fixed by adding `read_body_limited()` with 8MB cap and `ResponseTooLarge` error variant.

### [HIGH] SNMP Walk Infinite Loop (snmp_client.rs)
**Source:** External security review 2026-03-25
**Fixed:** v0.3.2

All 7 SNMP walk functions now check OID monotonicity (break if OID doesn't strictly advance) and enforce a 10,000-iteration cap.

### [MEDIUM] DNS Deviation Query Nondeterminism (policy_deviation_detector.rs)
**Source:** External review 2026-03-25
**Status:** Already fixed in v0.2.4

Query groups by all identity columns `(src_mac, src_ip, src_vlan, dst_ip)` — no `MAX()` aggregation. Fixed in v0.2.4.

### [MEDIUM] VLAN/Global Policy Merge on Authorize (policy_deviations.rs)
**Source:** External review 2026-03-25
**Status:** Already fixed in v0.2.4

Authorize action filters `p.vlan_scope.is_some()` to merge only VLAN-scoped targets, keeping global policies separate. Fixed in v0.2.4.

### [MEDIUM] Missing Jitter in Exponential Backoff (task_supervisor.rs)
**Source:** External review 2026-03-25
**Status:** Already fixed prior to review

Backoff includes ±25% jitter: `rand::random::<f64>() * 0.5 + 0.75` (line 182).

### [MEDIUM] Manual UTF-8 Decoding in SwOS Client (swos_client.rs)
**Source:** External security review 2026-03-25
**Fixed:** v0.3.2

`decode_hex_string` replaced manual UTF-8 state machine with `String::from_utf8_lossy()`.

### [MEDIUM] Repetitive Encryption Boilerplate (secrets.rs)
**Source:** External security review 2026-03-25
**Fixed:** v0.3.2

Extracted `encrypt_value()` helper method. All 9 encryption call sites across 4 functions now use the shared helper.

### [LOW] Magic Numbers for IANA ifType (snmp_profile.rs)
**Source:** External review 2026-03-25
**Status:** Already fixed prior to review

Named constants `IFTYPE_L2_VLAN` and `IFTYPE_SOFTWARE_LOOPBACK` are used.

### [LOW] Commented-Out Vendor Profile Code (snmp_profile.rs)
**Source:** External review 2026-03-25
**Status:** Already removed prior to review

The commented code was already removed. The reviewer was working from an older snapshot.

### [LOW] ThreadRng for Encryption Nonces (secrets.rs)
**Source:** External security review 2026-03-25
**Fixed:** v0.3.5 (development)

All cryptographic and session random generation now uses `OsRng.try_fill_bytes()` instead of `rand::random()` (ThreadRng). 13 call sites across 6 files updated.

### [MEDIUM] Syslog Provisioning: Invalid `bsd-syslog` Field
**Source:** Internal testing 2026-04-01
**Fixed:** v0.4.0

Syslog provisioning used a `bsd-syslog` field that doesn't exist in RouterOS. Changed to `remote-log-format: syslog`. Additionally, the action name `ion-drift` contained a hyphen which RouterOS rejects (alphanumeric only); changed to `iondrift`.

### [MEDIUM] `remote_port` Deserialization Failure
**Source:** Internal testing 2026-04-01
**Fixed:** v0.4.0

RouterOS returns the syslog `remote_port` value as a string, but the deserializer expected an integer. Added `ros_u32_opt` deserializer to handle string-to-integer conversion.

### [MEDIUM] Syslog `src-address` Accepted Hostname
**Source:** Internal testing 2026-04-01
**Fixed:** v0.4.0

Syslog provisioning was sending a hostname for `src-address`, but RouterOS requires an IP address. Fixed to send the resolved IP.

### [MEDIUM] Topology Ghost Nodes from Switch Interface MACs
**Source:** Internal testing 2026-04-01
**Fixed:** v0.4.0

Switch interface MACs were appearing as phantom endpoint nodes in the topology. Added switch-local MAC filtering to exclude them.

### [MEDIUM] MNDP Stale Neighbor Persistence
**Source:** Internal testing 2026-04-01
**Fixed:** v0.4.0

Stale MNDP entries persisted indefinitely, creating ghost neighbors in topology. Added 4-hour TTL neighbor pruning.

### [MEDIUM] False BFS Adjacency via Management VLAN MNDP
**Source:** Internal testing 2026-04-01
**Fixed:** v0.4.0

MNDP on the management VLAN created false direct paths between non-adjacent devices. BFS depth calculation now uses backbone links only for adjacency.

### [MEDIUM] Stale Inference Bindings Not Overwritten
**Source:** Internal testing 2026-04-01
**Fixed:** v0.4.0

Inference binding results were not pre-populating the identity builder, so stale bindings persisted even after new inference data was available. Inference results now pre-populate the identity builder.

## Accepted

### [LOW] Module API v1.0 — Connection / Snapshot / DeviceManager state reads not yet wired
**Source:** Internal review 2026-04-10

The `ConnectionRead`, `SnapshotRead`, and `DeviceManagerRead` traits are defined in `ion-drift-module-api` and modules can declare `StateReads::connection`, `.snapshot`, and `.devices` capabilities. However, the host currently passes `None` for these handles in `main.rs` — the corresponding `cx.connection()`, `cx.snapshot()`, and `cx.devices()` accessors return `None` even when the capability is declared. The traits exist as forward-compatible scaffolding; concrete host-backed implementations will land in a future minor bump (1.1+). Modules that need this data should treat the traits as not-yet-wired and reach into the authoritative stores via their own host integration (which is not stable across Drift versions). Documented in `docs/module-developer-guide.md` and in the trait doc comments.

### [LOW] Module API v1.0 — Event lag silently dropped at forwarder boundary
**Source:** External review 2026-04-09

The per-kind event bus runs an internal forwarder task per declared subscription kind that pulls from the kind's `tokio::sync::broadcast` channel and pushes events into a per-handle mpsc. If a forwarder cannot keep up (the broadcast channel overflows), the lag is silently dropped — modules do NOT see `EventError::Lagged` from `EventReceiver::recv()`. The error variant exists in the public enum for forward compatibility. Modules that are sensitive to missed events should reconcile state from authoritative stores (`cx.behavior()` etc.) on a periodic timer rather than relying on event delivery. A future minor bump may surface per-kind lag through diagnostic counters or a separate channel.

### [LOW] Module API v1.0 — No `Module::health` or metrics surface
**Source:** External review 2026-04-09 (R1) — dropped from v1.0 per YAGNI

The `Module::health` lifecycle method, `HealthEndpoint`, `MetricsCollector`, and `MetricsHandle` types were intentionally removed from the v1.0 contract. They were placeholder shapes with no host implementation, and freezing them into a stable contract would have created a semver trap. Modules can use `tracing` for diagnostics. Health and metrics will return as additive minor bumps in 1.x once the host has a real implementation (e.g. a Prometheus endpoint). Until then, the `/api/system/modules` listing endpoint returns module status but no per-module liveness probe.

### [LOW] Module API v1.0 — Modules run in-process, no hard sandbox
**Source:** Internal review 2026-04-10

Modules execute in the same process as Drift core. The capability handle pattern, namespace-scoped secrets, isolated SQLite, panic guards, and read-only state traits are defense-in-depth boundaries — they protect against accidents and misconfiguration, not against modules that want to break out via `unsafe`, filesystem access, network calls, or arbitrary process state. Operators should treat composed module binaries with the same trust they extend to any first-party Drift binary. There is no plan to add a true sandbox in the 1.x line; multi-tenant or untrusted-module deployments are explicitly out of scope.

### [MEDIUM] Baseline Poisoning During Learning Window (behavior.rs)
**Source:** External security review 2026-04-07

If an attacker has persistent access to a device during its learning period, low-volume malicious traffic (beaconing, slow exfil) will be incorporated into the device's baseline. After graduation, the anomaly detector treats that traffic as normal. This is an inherent limitation of behavioral baselining shared by all NDR products (Darktrace, Vectra, ExtraHop). Mitigation: reset a device's baseline via `DELETE /api/behavior/{mac}/baseline` if compromise is suspected during or after the learning window.

### [MEDIUM] Router Policy String in Permission Pre-check Response (system.rs)
**Source:** External security review 2026-04-07
**Fixed:** v0.4.1

The provisioning permission pre-check endpoint returned the raw RouterOS policy string (e.g., `read,write,api,!ftp`) to the frontend. While the endpoint is admin-only, this exposes the API user's exact router capabilities if an admin session is compromised. Fixed by adding `#[serde(skip_serializing)]` to the `policy` field — the frontend only needs `has_write` and `missing_policies`.

### [LOW] Default Router Credentials in Library (client.rs)
**Source:** External security review 2026-03-25

`DEFAULT_ROUTER_HOST` (`192.168.88.1`) and `DEFAULT_ROUTER_USERNAME` (`admin`) are MikroTik factory defaults used as config fallbacks. Validation logic prevents silent use — the setup wizard requires explicit credentials. These defaults match the vendor's factory configuration and are documented in the Quick Start guide.

## Won't Fix

### [LOW] Panic Message Information Leak (task_supervisor.rs)
**Source:** External review 2026-03-25

Panic payloads are logged directly. We don't put secrets in `expect()` messages, and these are container-internal logs, not user-facing output. The sanitization overhead isn't warranted.

### [LOW] Policy Lookup Mixed Responsibilities (behavior.rs)
**Source:** External review 2026-03-25

`get_policies_for_service` combines fetching, filtering, and VLAN matching in one method. This is a style/refactor suggestion, not a bug. The current implementation is correct and the method is well-scoped. Refactoring would add abstraction without reducing defect risk.
