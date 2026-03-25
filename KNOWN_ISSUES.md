# Known Issues

Tracked issues from external code reviews and internal testing.

## Resolved

### [HIGH] Blocking SQLite I/O in StatsStore (stats_store.rs)
**Source:** External review 2026-03-25
**Fixed:** `16b587c` (development)

StatsStore used `tokio::sync::Mutex` with synchronous rusqlite calls, blocking Tokio worker threads during I/O and WAL checkpoints. Fixed by switching to `std::sync::Mutex` + `spawn_blocking` for all database operations.

### [HIGH] Uncaught Synchronous Panic in Task Supervisor (task_supervisor.rs)
**Source:** External review 2026-03-25
**Status:** Already fixed prior to review

The factory function call is wrapped in `std::panic::catch_unwind` (lines 121-130). The reviewer was working from an older snapshot.

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

### [LOW] Magic Numbers for IANA ifType (snmp_profile.rs)
**Source:** External review 2026-03-25
**Status:** Already fixed prior to review

Named constants `IFTYPE_L2_VLAN` and `IFTYPE_SOFTWARE_LOOPBACK` are used.

## Won't Fix

### [LOW] Panic Message Information Leak (task_supervisor.rs)
**Source:** External review 2026-03-25

Panic payloads are logged directly. We don't put secrets in `expect()` messages, and these are container-internal logs, not user-facing output. The sanitization overhead isn't warranted.

### [LOW] Commented-Out Vendor Profile Code (snmp_profile.rs)
**Source:** External review 2026-03-25

The commented code was already removed prior to review. The reviewer was working from an older snapshot.

### [LOW] Policy Lookup Mixed Responsibilities (behavior.rs)
**Source:** External review 2026-03-25

`get_policies_for_service` combines fetching, filtering, and VLAN matching in one method. This is a style/refactor suggestion, not a bug. The current implementation is correct and the method is well-scoped. Refactoring would add abstraction without reducing defect risk.

### [HIGH] Session Secret Fail-Open on Decrypt Error (main.rs)
**Source:** External security review 2026-03-25
**Fixed:** development (this session)

Secret decryption errors were logged but startup continued with an empty session secret, creating a fail-open path where sessions were signed with a predictable empty HMAC key. Fixed by making decrypt errors fatal (`anyhow::bail!`) and generating an ephemeral random secret on `Ok(None)`.

### [HIGH] Err/Ok(None) Conflation in Secret Loading (main.rs)
**Source:** External security review 2026-03-25
**Fixed:** development (this session)

Decrypt errors (`Err`) and missing secrets (`Ok(None)`) were both treated as "secret not found", allowing the env var migration path to trigger on KEK corruption. Fixed by making `Err` fatal and only allowing migration on `Ok(None)`.

### [HIGH] Router Queue Poller Starvation
**Source:** Internal testing 2026-03-25
**Fixed:** `16b587c` (development)

Low-priority pollers (`log_aggregation`, `behavior-fw-cache`) were permanently starved by a steady stream of higher-priority batches. Fixed with age-based priority promotion (batches waiting >120s promoted to High priority) and reduced starvation log noise (warn once per threshold crossing instead of every loop iteration).

## Open

### [HIGH] Unbounded HTTP Response Body (client.rs)
**Source:** External security review 2026-03-25

`MikrotikClient::handle_response()` reads the entire response body into memory via `resp.text().await` without a size limit. A misbehaving router returning a massive response could cause OOM. Should enforce a cap (e.g., 2MB).

### [HIGH] SNMP Walk Infinite Loop (snmp_client.rs)
**Source:** External security review 2026-03-25

SNMP walk functions don't verify that each returned OID is strictly greater than the previous. A buggy agent returning the same OID would loop indefinitely. Should track `last_oid` and break on non-advancing responses.

### [MEDIUM] Manual UTF-8 Decoding in SwOS Client (swos_client.rs)
**Source:** External security review 2026-03-25

`decode_hex_string` manually implements UTF-8 decoding instead of using `String::from_utf8_lossy()`. Custom encoding implementations are prone to subtle bugs. Should decode hex to `Vec<u8>` then use the standard library.

### [MEDIUM] Repetitive Encryption Boilerplate (secrets.rs)
**Source:** External security review 2026-03-25

AES-256-GCM encrypt logic (cipher creation, nonce generation, payload construction) is duplicated across `encrypt_secret`, `store_all`, `add_device`, and `update_device`. Should extract a private `encrypt_value()` helper to reduce drift risk.

### [LOW] ThreadRng for Encryption Nonces (secrets.rs)
**Source:** External security review 2026-03-25

`rand::random()` is used for AES-256-GCM nonces. While the default RNG is currently CSPRNG, explicit `OsRng` usage is preferred for cryptographic operations.

### [LOW] Default Router Credentials in Library (client.rs)
**Source:** External security review 2026-03-25

`DEFAULT_ROUTER_HOST` and `DEFAULT_ROUTER_USERNAME` constants exist as fallbacks. Validation logic prevents silent use, but removing defaults would be more defensive.
